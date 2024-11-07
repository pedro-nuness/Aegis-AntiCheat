#include <iostream>

#include <winsock2.h>
#include <ws2tcpip.h>

#include "Communication.h"

#include <algorithm>

#include "../../Globals/Globals.h"
#include "../../Systems/Memory/memory.h"
#include "../../Systems/LogSystem/Log.h"
#include "../../Systems/Utils/xorstr.h"
#include "../../Systems/Utils/utils.h"
#include "../../Systems/Injection/Injection.h"
#include "../../Client/client.h"
#include "../../Systems/Utils/StringCrypt/StringCrypt.h"

#pragma comment(lib, "Ws2_32.lib")


#include <nlohmann/json.hpp>

using json = nlohmann::json;

#define SALT xorstr_("pjA5w1hoyzKCFEnk19hwtB8K11rCkWU1")
#define communication_key xorstr_("bfdgsam8ujf80942unv08wdnb08adu98") // 32 bytes para AES-256
#define communication_iv xorstr_("nviuofdsanbv890j") // 16 bytes para AES


Communication::~Communication( ) {
	stop( );
}

void Communication::start( ) {
	m_running = true;
	m_thread = std::thread( &Communication::threadFunction , this );
}

void Communication::stop( ) {
	m_running = false;
	if ( m_thread.joinable( ) ) {
		m_thread.join( );
	}
}

bool Communication::isRunning( ) const {
	return m_running && m_healthy;
}

void Communication::reset( ) {
	// Implementation to reset the thread
	// Implementation to reset the thread
	if ( m_thread.joinable( ) ) {
		m_thread.join( );
		Utils::Get( ).WarnMessage( _COMMUNICATION , xorstr_( "Waiting detection thread" ) , YELLOW );
	}
	else
		Utils::Get( ).WarnMessage( _COMMUNICATION , xorstr_( "Detection thread stopped" ) , GREEN );

	start( );
}

void Communication::requestupdate( ) {
	this->m_healthy = false;
}

SOCKET Communication::openConnection( const char * ipAddress , int port ) {
	WSADATA wsaData;
	int iResult;

	// Inicializa Winsock
	iResult = WSAStartup( MAKEWORD( 2 , 2 ) , &wsaData );
	if ( iResult != 0 ) {
		return INVALID_SOCKET;
	}

	// Cria o socket do servidor
	SOCKET ListenSocket = socket( AF_INET , SOCK_STREAM , IPPROTO_TCP );
	if ( ListenSocket == INVALID_SOCKET ) {
		WSACleanup( );
		return INVALID_SOCKET;
	}

	// Define o endereço e porta
	sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons( port );

	// Configura o IP do servidor
	if ( inet_pton( AF_INET , ipAddress , &serverAddr.sin_addr ) <= 0 ) {
		Utils::Get( ).WarnMessage( _COMMUNICATION , xorstr_( "can't convert ip address" ) , RED );
		closesocket( ListenSocket );
		WSACleanup( );
		return INVALID_SOCKET;
	}

	// Associa o socket com o endereço e porta
	iResult = bind( ListenSocket , ( SOCKADDR * ) &serverAddr , sizeof( serverAddr ) );
	if ( iResult == SOCKET_ERROR ) {
		Utils::Get( ).WarnMessage( _COMMUNICATION , xorstr_( "binding error" ) , RED );
		closesocket( ListenSocket );
		WSACleanup( );
		return INVALID_SOCKET;
	}

	return ListenSocket;
}

void Communication::closeconnection( SOCKET socket ) {
	closesocket( socket );
	WSACleanup( );
}

SOCKET Communication::listenForClient( SOCKET ListenSocket , int timeoutSeconds ) {
	// Coloca o socket em modo de escuta
	int iResult = listen( ListenSocket , SOMAXCONN );
	if ( iResult == SOCKET_ERROR ) {
		Utils::Get( ).WarnMessage( _COMMUNICATION , xorstr_( "can't listen client" ) , WHITE );
		closesocket( ListenSocket );
		WSACleanup( );
		return INVALID_SOCKET;
	}

	// Configura a estrutura fd_set para monitorar o socket
	fd_set readfds;
	FD_ZERO( &readfds );
	FD_SET( ListenSocket , &readfds );

	// Define o timeout
	timeval timeout;
	timeout.tv_sec = timeoutSeconds;  // Segundos
	timeout.tv_usec = 0;              // Microsegundos

	// Usa select para aguardar por conexões com timeout
	iResult = select( 0 , &readfds , NULL , NULL , &timeout );
	if ( iResult == SOCKET_ERROR ) {
		Utils::Get( ).WarnMessage( _COMMUNICATION , xorstr_( "can't get server" ) , RED );
		return INVALID_SOCKET;
	}
	else if ( iResult == 0 ) {
		Utils::Get( ).WarnMessage( _COMMUNICATION , xorstr_( "connection time out" ) , RED );
		return INVALID_SOCKET;  // Timeout ocorreu
	}

	// Aceita a conexão do cliente
	SOCKET ClientSocket = accept( ListenSocket , NULL , NULL );
	if ( ClientSocket == INVALID_SOCKET ) {
		Utils::Get( ).WarnMessage( _COMMUNICATION , xorstr_( "can't accept connection" ) , RED );
		return INVALID_SOCKET;
	}

	return ClientSocket;
}

bool Communication::sendMessage( SOCKET ClientSocket , std::string message ) {


	if ( this->ClientSocket == INVALID_SOCKET ) {
		Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Invalid socket." ) , RED );
		return false;
	}

	std::string encryptedMessage;

	if ( !Utils::Get( ).encryptMessage( message , encryptedMessage , communication_key , communication_iv ) ) {
		Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Failed to encrypt the message." ) , RED );
		return false;
	}

	long int messageSize = encryptedMessage.size( );
	std::string messageSizeStr = std::to_string( messageSize );
	int SizeBackup = messageSizeStr.size( );
	//message_size bufer = char * 35 - 1 ( end of the strin \0 )
	messageSizeStr.insert( 0 , 34 - SizeBackup , '0' );  // Insere 'quantidade_zeros' zeros no início
	// 0000001348
	if ( send( this->ClientSocket , messageSizeStr.c_str( ) , messageSizeStr.size( ) , 0 ) == SOCKET_ERROR ) {
		Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Failed to send message size." ) , RED );
		return false;
	}

	//pause, so the server can process it
	std::this_thread::sleep_for( std::chrono::milliseconds( 50 ) );

	int totalSent = 0;
	while ( totalSent < messageSize ) {
		int sent = send( this->ClientSocket , encryptedMessage.c_str( ) + totalSent , messageSize - totalSent , 0 );
		if ( sent == SOCKET_ERROR ) {
			Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Failed to send encrypted message." ) , RED );
			closesocket( this->ClientSocket );
			WSACleanup( );
			return false;
		}
		totalSent += sent;
	}


	return true;
}

bool isNumeric( const std::string & str );

std::string Communication::receiveMessage( SOCKET ClientSocket , int time ) {
	//buffer size
	char sizeBuffer[ 35 ];
	int received = recv( ClientSocket , sizeBuffer , sizeof( sizeBuffer ) - 1 , 0 );
	if ( received <= 0 ) {
		Utils::Get( ).WarnMessage( _COMMUNICATION , xorstr_( "Failed to receive message size." ) , COLORS::RED );
		closesocket( ClientSocket );
		return xorstr_( "" );
	}
	sizeBuffer[ received ] = '\0';
	std::string sizeString( sizeBuffer );


	if ( !isNumeric( sizeString ) ) {
		closesocket( ClientSocket );
		Utils::Get( ).WarnMessage( _COMMUNICATION , xorstr_( "Received invalid size: " ) + sizeString , COLORS::RED );


		return xorstr_( "" );
	}

	int messageSize;
	try {
		messageSize = std::stoi( sizeString );
	}
	catch ( const std::invalid_argument & ) {
		Utils::Get( ).WarnMessage( _COMMUNICATION , xorstr_( "Invalid message size" ) , COLORS::RED );
		closesocket( ClientSocket );
		return xorstr_( "" );
	}
	catch ( const std::out_of_range & ) {
		Utils::Get( ).WarnMessage( _COMMUNICATION , xorstr_( "Message size out of range" ) , COLORS::RED );
		closesocket( ClientSocket );
		return xorstr_( "" );
	}

	const int MAX_MESSAGE_SIZE = 50 * 1024 * 1024; // Limite de 50 MB
	if ( messageSize <= 0 || messageSize > MAX_MESSAGE_SIZE ) {
		Utils::Get( ).WarnMessage( _COMMUNICATION , xorstr_( "Invalid message size." ) , COLORS::RED );
		closesocket( ClientSocket );
		return xorstr_( "" );
	}

	char * buffer = new( std::nothrow ) char[ messageSize ];
	if ( !buffer ) {
		Utils::Get( ).WarnMessage( _COMMUNICATION , xorstr_( "Failed to allocate memory for message." ) , COLORS::RED );
		closesocket( ClientSocket );
		return xorstr_( "" );
	}

	bool FailedReceive = false;
	int totalReceived = 0;
	while ( totalReceived < messageSize ) {
		received = recv( ClientSocket , buffer + totalReceived , messageSize - totalReceived , 0 );
		if ( received <= 0 ) {
			Utils::Get( ).WarnMessage( _COMMUNICATION , xorstr_( "Failed to receive encrypted message." ) , COLORS::RED );
			delete[ ] buffer;
			closesocket( ClientSocket );
			FailedReceive = true;
			break;
		}
		totalReceived += received;
	}

	if ( FailedReceive ) {
		Utils::Get( ).WarnMessage( _COMMUNICATION , xorstr_( "Failed to receive message" ) , COLORS::RED );
		return xorstr_( "" );
	}

	if ( totalReceived < messageSize ) {
		Utils::Get( ).WarnMessage( _COMMUNICATION , xorstr_( "Received Missing message" ) , COLORS::RED );
		delete[ ] buffer;
		closesocket( ClientSocket );
		return xorstr_( "" );
	}

	std::string encryptedMessage( buffer , messageSize );
	delete[ ] buffer;

	if ( encryptedMessage.empty( ) ) {
		Utils::Get( ).WarnMessage( _COMMUNICATION , xorstr_( "Empty message received." ) , COLORS::RED );
		closesocket( ClientSocket );
		return xorstr_( "" );
	}

	if ( !Utils::Get( ).decryptMessage( encryptedMessage , encryptedMessage , communication_key , communication_iv ) ) {
		Utils::Get( ).WarnMessage( _COMMUNICATION , xorstr_( "Failed to decrypt the message." ) , COLORS::RED );
		closesocket( ClientSocket );
		return xorstr_( "" );
	}

	return encryptedMessage;
}


#define now std::chrono::high_resolution_clock::now()

bool Communication::PingInTime( ) {
	std::chrono::duration<double> elapsed = now - this->LastClientPing;
	return elapsed.count( ) <= this->PingLimit;
}

void Communication::UpdatePingTime( ) {
	this->LastClientPing = now;
}

void Communication::HandleMissingPing( ) {

	closeconnection( ClientSocket );
	closeconnection( ListenSocket );

	if ( Mem::Get( ).IsPIDRunning( Globals::Get( ).ProtectProcess ) ) {
		// Usando RAII para garantir que o handle seja fechado corretamente
		HANDLE hProcess = Mem::Get( ).GetProcessHandle( Globals::Get( ).ProtectProcess );
		auto processHandleGuard = std::unique_ptr<void , decltype( &CloseHandle )>( hProcess , CloseHandle );

		if ( hProcess != NULL ) {
			while ( !TerminateProcess( hProcess , 0 ) ) {
				std::this_thread::sleep_for( std::chrono::milliseconds( 250 ) );
			}
			LogSystem::Get( ).Log( xorstr_( "[303] Can't find client answer!" ) );
		}
	}
	else {
		LogSystem::Get( ).Log( xorstr_( "[303] Can't find client answer!" ) );
	}
}

bool Communication::InitializeClient( ) {
	return Injector::Get( ).Inject( xorstr_( "winsock.dll" ) , Globals::Get( ).ProtectProcess ) == 1;
}

bool Communication::SendPasswordToServer( ) {

	{
		std::string Password = Utils::Get( ).GenerateRandomKey( 256 );
		sendMessage( ClientSocket , Password.c_str( ) );


		//expected response
		this->ExpectedMessage = Mem::Get( ).GenerateHash( Password + SALT );
	}

	std::this_thread::sleep_for( std::chrono::seconds( 2 ) );

	return true;
}

bool Communication::CheckReceivedPassword( ) {
	//expected hash

	//Allocate memory for the uncrypted message
	{
	
		std::string ReceivedPassword;
		//Wait for the message
		ReceivedPassword = receiveMessage( ClientSocket , 10 );

		if ( ReceivedPassword != this->ExpectedMessage ) {
			closeconnection( ListenSocket );
			std::cout << ReceivedPassword << ", " << CommunicationHash << std::endl;
			std::this_thread::sleep_for( std::chrono::seconds( 10 ) );
			LogSystem::Get( ).Log( xorstr_( "[802] client hash mismatch!\n" ) );
			return false;
		}
		else {
		}
	}

	return true;
}

void Communication::SendPingToServer( ) {
	while ( true ) {

		// Envia PING para o servidor
		client::Get( ).SendPingToServer( );

		std::this_thread::sleep_for( std::chrono::seconds( 10 ) );
	}
}

void Communication::OpenRequestServer( ) {

	SOCKET ListenSock = openConnection( xorstr_( "127.0.0.10" ) , 4444 );
	if ( ListenSock == INVALID_SOCKET ) {
		LogSystem::Get( ).Log( xorstr_( "[601] Can't open listener connection!" ) );
	}

	while ( true ) {
		Utils::Get( ).WarnMessage( _COMMUNICATION , xorstr_( "waiting client connection..." ) , WHITE );
		//24 hours delay
		SOCKET ClientSock = listenForClient( ListenSock , 86400 );
		if ( ClientSock == INVALID_SOCKET ) {
			closeconnection( ListenSock );
			LogSystem::Get( ).Log( xorstr_( "[601] Can't open client connection!" ) );
		}

		std::string MessageReceived = receiveMessage( ClientSock , 10 );
		if ( MessageReceived.empty( ) ) {
			Utils::Get( ).WarnMessage( _COMMUNICATION , xorstr_( "received empty message from client" ) , YELLOW );
			continue;
		}

		json js;
		try {
			js = json::parse( MessageReceived );
		}
		catch ( json::parse_error error ) {
			Utils::Get( ).WarnMessage( _COMMUNICATION , xorstr_( "failed to parse message to json!" ) , YELLOW );
			continue;
		}
	}
}

void Communication::threadFunction( ) {

	Utils::Get( ).WarnMessage( _COMMUNICATION , xorstr_( "thread started sucessfully " ) , GREEN );

	// Envia PING para o servidor
	if ( !client::Get( ).SendPingToServer( ) ) {
		LogSystem::Get( ).LogWithMessageBox( xorstr_( "[401] Server is offline!" ) , xorstr_( "Server is offline!" ) );
	}

	ListenSocket = openConnection( xorstr_( "127.0.0.10" ) , 8080 );
	if ( ListenSocket == INVALID_SOCKET ) {
		LogSystem::Get( ).Log( xorstr_( "[801] Can't open listener connection!" ) );
	}

	Utils::Get( ).WarnMessage( _COMMUNICATION , xorstr_( "waiting client connection..." ) , WHITE );

	if ( !InitializeClient( ) ) {
		LogSystem::Get( ).Log( xorstr_( "[0001] Can't init client!" ) );
	}

	Utils::Get( ).WarnMessage( _COMMUNICATION , xorstr_( "started client sucessfully" ) , WHITE );

	ClientSocket = listenForClient( ListenSocket , 10 );
	if ( ClientSocket == INVALID_SOCKET ) {
		closeconnection( ListenSocket );
		LogSystem::Get( ).Log( xorstr_( "[801] Can't open client connection!" ) );
	}

	Utils::Get( ).WarnMessage( _COMMUNICATION , xorstr_( "client connected sucessfully" ) , GREEN );
	std::this_thread::sleep_for( std::chrono::seconds( 5 ) );

	if ( !SendPasswordToServer( ) ) {
		LogSystem::Get( ).Log( xorstr_( "[0001] Failed to send password to server!" ) );
	}

	if ( !CheckReceivedPassword( ) ) {
		LogSystem::Get( ).Log( xorstr_( "[0001] Hash mismatch!" ) );
	}

	std::thread( &receiver::InitializeConnection , this->ServerReceiver ).detach( );
	std::thread( &Communication::SendPingToServer , this ).detach( );

	Globals::Get( ).VerifiedSession = true;

	this->LastClientPing = now;

	while ( m_running ) {
		m_healthy = true;

		this->ExpectedMessage = Mem::Get( ).GenerateHash( this->ExpectedMessage + SALT );
		// Envia mensagem para o cliente
		sendMessage( ClientSocket , this->ExpectedMessage );


		//Expected response
		this->ExpectedMessage = Mem::Get( ).GenerateHash( this->ExpectedMessage + SALT);
		// Recebe mensagem do cliente
		std::string message = receiveMessage( ClientSocket , 20 );

		if ( !message.empty( ) ) {
			if ( message != this->ExpectedMessage ) {
				closeconnection( ClientSocket );
				closeconnection( ListenSocket );

				LogSystem::Get( ).Log( xorstr_( "[802] client hash mismatch!\n" ) );
			}
			else {
				Utils::Get( ).WarnMessage( LIGHT_WHITE , xorstr_( "PING" ) , this->ExpectedMessage , GRAY );
				UpdatePingTime( );
			}
		}
		else if ( !PingInTime( ) ) {
			HandleMissingPing( );
		}

		// Aguarda por 5 segundos antes do próximo loop
		std::this_thread::sleep_for( std::chrono::seconds( 5 ) );
	}

	closeconnection( ClientSocket );
	closeconnection( ListenSocket );
}