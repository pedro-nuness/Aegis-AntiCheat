#include <iostream>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <algorithm>

#include "Communication.h"
#include "../../Systems/LogSystem/Log.h"
#include "../../Systems/Utils/xorstr.h"
#include "../../Systems/Utils/StringCrypt/StringCrypt.h"
#include "../../Systems/Memory/memory.h"
#include "../../Systems/Globals/Globals.h"
#include "../../Systems/Utils/utils.h"

#pragma comment(lib, "Ws2_32.lib")


#define SALT xorstr_("pjA5w1hoyzKCFEnk19hwtB8K11rCkWU1")
#define communication_key xorstr_("bfdgsam8ujf80942unv08wdnb08adu98") // 32 bytes para AES-256
#define communication_iv xorstr_("nviuofdsanbv890j") // 16 bytes para AES

Communication::Communication( ) {

}

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
	this->m_running = false;
	std::cout << xorstr_( "[communication] resetting thread!\n" );
	if ( m_thread.joinable( ) ) {
		m_thread.join( );
	}

	this->m_running = true;

	start( );
}

void Communication::requestupdate( ) {
	this->m_healthy = false;
}

SOCKET Communication::openConnection( const char * serverIp , int serverPort ) {
	WSADATA wsaData;
	int iResult;

	// Inicializa Winsock
	iResult = WSAStartup( MAKEWORD( 2 , 2 ) , &wsaData );
	if ( iResult != 0 ) {
		std::cout << xorstr_( "WSAStartup falhou: " ) << iResult << std::endl;
		return INVALID_SOCKET;
	}

	// Cria o socket do cliente
	SOCKET ConnectSocket = socket( AF_INET , SOCK_STREAM , IPPROTO_TCP );
	if ( ConnectSocket == INVALID_SOCKET ) {
		std::cout << xorstr_( "Erro ao criar socket: " ) << WSAGetLastError( ) << std::endl;
		WSACleanup( );
		return INVALID_SOCKET;
	}

	// Define o endereço e porta do servidor
	sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons( serverPort );
	inet_pton( AF_INET , serverIp , &serverAddr.sin_addr );

	// Conecta ao servidor
	iResult = SOCKET_ERROR;
	int ConnectionTry = 0;
	while ( iResult == SOCKET_ERROR && ConnectionTry <= 3 ) {
		iResult = connect( ConnectSocket , ( SOCKADDR * ) &serverAddr , sizeof( serverAddr ) );
		ConnectionTry++;
		std::cout << xorstr_( "[CLIENT] Connection attempt!\n" );
		std::this_thread::sleep_for( std::chrono::seconds( 2 ) );
	}

	if ( iResult == SOCKET_ERROR ) {
		std::cout << xorstr_( "Erro ao conectar: " ) << WSAGetLastError( ) << std::endl;
		LogSystem::Get( ).Log( xorstr_( "[CLIENT][201] Can't connect to server!" ) );
		system( "pause" );
		closesocket( ConnectSocket );
		WSACleanup( );
		return INVALID_SOCKET;
	}

	return ConnectSocket;
}

void Communication::closeConnection( SOCKET socket ) {
	closesocket( socket );
	WSACleanup( );
}

bool Communication::sendMessage( SOCKET ClientSocket , std::string message ) {

	if ( ClientSocket == INVALID_SOCKET ) {
		Utils::Get( ).WarnMessage( LIGHT_BLUE , xorstr_( "communication" ) , xorstr_( "Invalid socket." ) , RED );
		return false;
	}

	std::string encryptedMessage;

	if ( !Utils::Get( ).encryptMessage( message , encryptedMessage , communication_key , communication_iv ) ) {
		Utils::Get( ).WarnMessage( LIGHT_BLUE , xorstr_( "communication" ) , xorstr_( "Failed to encrypt the message." ) , RED );
		return false;
	}

	long int messageSize = encryptedMessage.size( );

	std::string messageSizeStr = std::to_string( messageSize );
	int SizeBackup = messageSizeStr.size( );
	//message_size bufer = char * 35 - 1 ( end of the strin \0 )
	messageSizeStr.insert( 0 , 34 - SizeBackup , '0' );  // Insere 'quantidade_zeros' zeros no início
	// 0000001348

	if ( send( ClientSocket , messageSizeStr.c_str( ) , messageSizeStr.size( ) , 0 ) == SOCKET_ERROR ) {
		Utils::Get( ).WarnMessage( LIGHT_BLUE , xorstr_( "communication" ) , xorstr_( "Failed to send message size." ) , RED );
		return false;
	}

	//pause, so the server can process it
	std::this_thread::sleep_for( std::chrono::milliseconds( 150 ) );

	int totalSent = 0;
	while ( totalSent < messageSize ) {
		int sent = send( ClientSocket , encryptedMessage.c_str( ) + totalSent , messageSize - totalSent , 0 );
		if ( sent == SOCKET_ERROR ) {
			Utils::Get( ).WarnMessage( LIGHT_BLUE , xorstr_( "communication" ) , xorstr_( "Failed to send encrypted message." ) , RED );
			closesocket( ClientSocket );
			WSACleanup( );
			return false;
		}
		totalSent += sent;
	}

	return true;
}

bool isNumeric( const std::string & str ) {
	return !str.empty( ) && std::all_of( str.begin( ) , str.end( ) , ::isdigit );
}

std::string Communication::receiveMessage( SOCKET ClientSocket , int time ) {
	char sizeBuffer[ 35 ];
	int received = recv( ClientSocket , sizeBuffer , sizeof( sizeBuffer ) - 1 , 0 );
	if ( received <= 0 ) {
		Utils::Get( ).WarnMessage( LIGHT_BLUE , xorstr_( "communication" ) , xorstr_( "Failed to receive message size." ) , COLORS::RED );
		closesocket( ClientSocket );
		return xorstr_( " " );
	}

	sizeBuffer[ received ] = '\0';
	std::string sizeString( sizeBuffer );




	if ( !isNumeric( sizeString ) ) {
		closesocket( ClientSocket );
		Utils::Get( ).WarnMessage( LIGHT_BLUE , xorstr_( "communication" ) , xorstr_( "Received invalid size: " ) + sizeString , COLORS::RED );
		return xorstr_( "" );
	}

	int messageSize;
	try {
		messageSize = std::stoi( sizeString );
	}
	catch ( const std::invalid_argument & ) {
		Utils::Get( ).WarnMessage( LIGHT_BLUE , xorstr_( "communication" ) , xorstr_( "Invalid message size" ) , COLORS::RED );
		closesocket( ClientSocket );
		return xorstr_( " " );
	}
	catch ( const std::out_of_range & ) {
		Utils::Get( ).WarnMessage( LIGHT_BLUE , xorstr_( "communication" ) , xorstr_( "Message size out of range" ) , COLORS::RED );
		closesocket( ClientSocket );
		return xorstr_( " " );
	}


	const int MAX_MESSAGE_SIZE = 50 * 1024 * 1024; // Limite de 50 MB
	if ( messageSize <= 0 || messageSize > MAX_MESSAGE_SIZE ) {
		Utils::Get( ).WarnMessage( LIGHT_BLUE , xorstr_( "communication" ) , xorstr_( "Invalid message size." ) , COLORS::RED );
		closesocket( ClientSocket );
		return xorstr_( " " );
	}

	char * buffer = new( std::nothrow ) char[ messageSize ];
	if ( !buffer ) {
		Utils::Get( ).WarnMessage( LIGHT_BLUE , xorstr_( "communication" ) , xorstr_( "Failed to allocate memory for message." ) , COLORS::RED );
		closesocket( ClientSocket );
		return xorstr_( " " );
	}

	bool FailedReceive = false;
	int totalReceived = 0;
	while ( totalReceived < messageSize ) {
		received = recv( ClientSocket , buffer + totalReceived , messageSize - totalReceived , 0 );
		if ( received <= 0 ) {
			Utils::Get( ).WarnMessage( LIGHT_BLUE , xorstr_( "communication" ) , xorstr_( "Failed to receive encrypted message." ) , COLORS::RED );
			delete[ ] buffer;
			closesocket( ClientSocket );
			FailedReceive = true;
			break;
		}
		totalReceived += received;
	}

	if ( FailedReceive ) {
		Utils::Get( ).WarnMessage( LIGHT_BLUE , xorstr_( "communication" ) , xorstr_( "Failed to receive" ) , COLORS::RED );
		return xorstr_( " " );
	}

	if ( totalReceived < messageSize ) {
		Utils::Get( ).WarnMessage( LIGHT_BLUE , xorstr_( "communication" ) , xorstr_( "Received missing message" ) , COLORS::RED );
		delete[ ] buffer;
		closesocket( ClientSocket );
		return xorstr_( " " );
	}

	std::string encryptedMessage( buffer , messageSize );
	delete[ ] buffer;

	if ( encryptedMessage.empty( ) ) {
		Utils::Get( ).WarnMessage( LIGHT_BLUE , xorstr_( "communication" ) , xorstr_( "Empty message received." ) , COLORS::RED );
		closesocket( ClientSocket );
		return xorstr_( " " );
	}

	if ( !Utils::Get( ).decryptMessage( encryptedMessage , encryptedMessage , communication_key , communication_iv ) ) {
		Utils::Get( ).WarnMessage( LIGHT_BLUE , xorstr_( "communication" ) , xorstr_( "Failed to decrypt the message." ) , COLORS::RED );
		closesocket( ClientSocket );
		return xorstr_( " " );
	}

	return encryptedMessage;
}



#define now std::chrono::high_resolution_clock::now()

bool Communication::PingInTime( ) {
	std::chrono::duration<double> elapsed = now - this->LastClientPing;
	std::cout << "Elapsed time with no ping: " << elapsed.count( ) << "\n";
	return elapsed.count( ) <= this->PingLimit;
}

void Communication::UpdatePingTime( ) {
	this->LastClientPing = now;
}


void Communication::threadFunction( ) {
	const char * ipAddress = "127.0.0.10";

	Utils::Get( ).WarnMessage( LIGHT_BLUE , xorstr_( "communication" ) , xorstr_( "Sucessfully attached" ) , WHITE );

	int ConnectionTries = 0;
	SOCKET ConnectSocket = openConnection( xorstr_( "127.0.0.10" ) , 8080 );

	if ( ConnectSocket == INVALID_SOCKET ) {
		LogSystem::Get( ).Log( xorstr_( "[701] Can't open connection!\n" ) );
	}

	std::cout << xorstr_( "[communication] Conectado ao servidor." ) << std::endl;


	//Allocate memory for the uncrypted message
	{
		std::string Password;
		//Wait for the message

		Password = receiveMessage( ConnectSocket , 10 );
		//Password required
		this->ExpectedMessage = Mem::Get( ).GenerateHash( Password + SALT );
	}

	//Send the pasword + salt hash
	sendMessage( ConnectSocket , this->ExpectedMessage );


	Globals::Get( ).VerifiedSession = true;

	while ( m_running ) {
		std::this_thread::sleep_for( std::chrono::seconds( 5 ) );
		this->m_healthy = true;

		//The message expected
		this->ExpectedMessage = Mem::Get( ).GenerateHash( this->ExpectedMessage + SALT );

		// Recebe mensagem do cliente
		std::string Message = receiveMessage( ConnectSocket , 10 );
		if ( !Message.empty( ) ) {
			if ( Message != this->ExpectedMessage ) {
				LogSystem::Get( ).Log( xorstr_( "[client][802] client hash mismatch!\n" ) );
			}
			else {
				Utils::Get( ).WarnMessage( LIGHT_WHITE , xorstr_( "PING" ) , this->ExpectedMessage , GRAY );
				//update message sent			
				UpdatePingTime( );
			}
		}
		else if ( !PingInTime( ) ) {
			LogSystem::Get( ).Log( xorstr_( "[client][303] Can`t find server answer!" ) );
		}

		this->ExpectedMessage = Mem::Get( ).GenerateHash( this->ExpectedMessage + SALT );
		sendMessage( ConnectSocket , this->ExpectedMessage );
		this->m_healthy = true;
	}

	closeConnection( ConnectSocket );
}