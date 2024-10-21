#include <iostream>

#include <winsock2.h>
#include <ws2tcpip.h>


#include "Communication.h"

#include "../../Globals/Globals.h"
#include "../../Systems/Memory/memory.h"
#include "../../Systems/LogSystem/Log.h"
#include "../../Systems/Utils/xorstr.h"
#include "../../Systems/Utils/utils.h"
#include "../../Systems/Injection/Injection.h"
#include "../../Client/client.h"
#include "../../Systems/Utils/StringCrypt/StringCrypt.h"

#pragma comment(lib, "Ws2_32.lib")


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

SOCKET Communication::openConnection( const char * ipAddress ) {
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
	serverAddr.sin_port = htons( 8080 );

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

bool Communication::sendMessage( SOCKET ClientSocket , const char * message ) {
	int iResult = send( ClientSocket , message , ( int ) strlen( message ) , 0 );
	if ( iResult == SOCKET_ERROR ) {
		Utils::Get( ).WarnMessage( _COMMUNICATION , xorstr_( "can't send message" ) , RED );
		return false;
		LogSystem::Get( ).Log( xorstr_( "[105] Can't send message!" ) );
	}

	return true;
}

std::string Communication::receiveMessage( SOCKET ClientSocket , int time ) {
	char recvbuf[ 512 ];
	int iResult;

	int timeout = time * 1000; // Timeout in milliseconds
	setsockopt( ClientSocket , SOL_SOCKET , SO_RCVTIMEO , ( const char * ) &timeout , sizeof( timeout ) );

	iResult = recv( ClientSocket , recvbuf , 512 , 0 );
	if ( iResult > 0 ) {
		recvbuf[ iResult ] = '\0'; // Ensure null-termination of the received string
		std::string response = std::string( recvbuf );
		RtlZeroMemory( recvbuf , sizeof( recvbuf ) );
		return response;
	}
	else if ( iResult == 0 ) {
		LogSystem::Get( ).Log( xorstr_( "[900] Connection closed" ) );
	}
	else {
		if ( WSAGetLastError( ) == WSAETIMEDOUT ) {
			LogSystem::Get( ).Log( xorstr_( "[902] Receive timeout" ) );
		}
		else {
			LogSystem::Get( ).Log( xorstr_( "[901] Error receiving message" ) );
		}
	}
	return "";
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
	std::string * DecryptedMessage = StringCrypt::Get( ).DecryptString( xorstr_( "a477c5772e93d5a7f3f91d766d249e0a63b8bef5" ) );

	if ( DecryptedMessage->empty( ) ) {
		StringCrypt::Get( ).CleanString( DecryptedMessage );
		LogSystem::Get( ).Log( xorstr_( "[203] Can't read encrypted message!" ) );
	}

	std::cout << "Password: " << *DecryptedMessage << "\n";

	this->Message = Mem::Get( ).GenerateHash( *DecryptedMessage );

	sendMessage( ClientSocket , DecryptedMessage->c_str( ) );

	StringCrypt::Get( ).CleanString( DecryptedMessage );
	std::this_thread::sleep_for( std::chrono::seconds( 2 ) );

	return true;
}

bool Communication::CheckReceivedPassword( ) {
	//expected hash
	this->CommunicationHash = xorstr_( "90ed071b4c6ba84ada3b57733b60bc092c758930" );

	//Allocate memory for the uncrypted message
	auto * FirstMessage = new std::string;
	FirstMessage->reserve( 32 ); // Pre-allocate memory

	//Wait for the message
	while ( FirstMessage->empty( ) ) {
		*FirstMessage = receiveMessage( ClientSocket , 10 );
	}

	//Convert the message to hash, let`s check if it matches
	std::string ReceivedHash = Mem::Get( ).GenerateHash( FirstMessage->c_str( ) );

	//Free string memory
	StringCrypt::Get( ).CleanString( FirstMessage );

	if ( ReceivedHash != this->CommunicationHash ) {
		closeconnection( ListenSocket );
		LogSystem::Get( ).Log( xorstr_( "[802] client hash mismatch!\n" ) );
		return false;
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

void Communication::threadFunction( ) {

	Utils::Get( ).WarnMessage( _COMMUNICATION , xorstr_( "thread started sucessfully " ) , GREEN );

	ListenSocket = openConnection( xorstr_( "127.0.0.10" ) );
	if ( ListenSocket == INVALID_SOCKET ) {
		LogSystem::Get( ).Log( xorstr_( "[801] Can't open listener connection!" ) );
	}

	Utils::Get( ).WarnMessage( _COMMUNICATION , xorstr_( "waiting client connection..." ) , WHITE );

#ifdef _DEBUG
#else
	/*
	if ( Utils::Get( ).ExistsFile( xorstr_( "winsock.dll" ) ) ) {
		std::string originalHash = xorstr_( "ac85965ab72a6bfd5d15e56c0d4beffcfd8ccc63" );
		if ( Mem::Get( ).GetFileHash( xorstr_( "winsock.dll" ) ) != originalHash ) {
			LogSystem::Get( ).Log( xorstr_( "[0002] cant get client memory" ) );
		}
	}
	else {
		LogSystem::Get( ).Log( xorstr_( "[005] invalid files" ) );
	}
	*/
#endif

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

	if ( !SendPasswordToServer( ) ) {
		LogSystem::Get( ).Log( xorstr_( "[0001] Failed to send password to server!" ) );
	}

	if ( !CheckReceivedPassword( ) ) {
		LogSystem::Get( ).Log( xorstr_( "[0001] Hash mismatch!" ) );
	}

	// Envia PING para o servidor
	if ( !client::Get( ).SendPingToServer( ) ) {
		LogSystem::Get( ).Log( xorstr_( "[401] Server is offline!" ) );
	}

	std::thread( &receiver::InitializeConnection , this->ServerReceiver ).detach( );
	std::thread( &Communication::SendPingToServer , this ).detach( );


	Globals::Get( ).VerifiedSession = true;

	this->LastClientPing = now;

	while ( m_running ) {
		m_healthy = true;

		// Recebe mensagem do cliente
		std::string message = receiveMessage( ClientSocket , 10 );

		if ( !message.empty( ) ) {
			if ( message != this->CommunicationHash ) {
				closeconnection( ClientSocket );
				closeconnection( ListenSocket );

				LogSystem::Get( ).Log( xorstr_( "[802] client hash mismatch!\n" ) );
			}
			else {
				Utils::Get( ).WarnMessage( LIGHT_WHITE , xorstr_( "PING" ) , this->CommunicationHash , GRAY );
				this->CommunicationHash = Mem::Get( ).GenerateHash( this->CommunicationHash );
				UpdatePingTime( );
			}
		}
		else if ( !PingInTime( ) ) {
			HandleMissingPing( );
		}

		// Envia mensagem para o cliente
		sendMessage( ClientSocket , this->Message.c_str( ) );
		this->Message = Mem::Get( ).GenerateHash( this->Message );

	

		// Aguarda por 5 segundos antes do próximo loop
		std::this_thread::sleep_for( std::chrono::seconds( 5 ) );
	}

	closeconnection( ClientSocket );
	closeconnection( ListenSocket );
}