#include <iostream>

#include <winsock2.h>
#include <ws2tcpip.h>

#include "Communication.h"
#include "../../Systems/LogSystem/Log.h"
#include "../../Systems/Utils/xorstr.h"
#include "../../Systems/Utils/StringCrypt/StringCrypt.h"
#include "../../Systems/Memory/memory.h"
#include "../../Systems/Globals/Globals.h"
#include "../../Systems/Utils/utils.h"

#pragma comment(lib, "Ws2_32.lib")

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
		std::cout << xorstr_("[CLIENT] Connection attempt!\n");
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

void Communication::sendMessage( SOCKET ConnectSocket , const char * message ) {
	int iResult = send( ConnectSocket , message , ( int ) strlen( message ) , 0 );
	if ( iResult == SOCKET_ERROR ) {
		std::cout << xorstr_( "Erro ao enviar mensagem: " ) << WSAGetLastError( ) << std::endl;
	}
}

std::string Communication::receiveMessage( SOCKET ClientSocket, int time ) {
	char recvbuf[ 512 ];
	int iResult;

	// Set a receive timeout of 5 seconds (5000 milliseconds)
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
		LogSystem::Get( ).Log( xorstr_( "[CLIENT][900] Connection closed" ) );
	}
	else {
		if ( WSAGetLastError( ) == WSAETIMEDOUT ) {
			LogSystem::Get( ).Log( xorstr_( "[CLIENT][902] Receive timeout" ) );
		}
		else {
			LogSystem::Get( ).Log( xorstr_( "[CLIENT][901] Can't receive message" ) );
		}
	}
	return "";
}


#define now std::chrono::high_resolution_clock::now()

bool Communication::PingInTime( ) {
	std::chrono::duration<double> elapsed = now - this->LastClientPing;
	std::cout << "Elapsed time with no ping: " << elapsed.count() << "\n";
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

	std::this_thread::sleep_for( std::chrono::seconds( 1 ) );

	StringCrypt::Get( ).Init( );

	std::string * DecryptedMessage = StringCrypt::Get( ).DecryptString( xorstr_( "90ed071b4c6ba84ada3b57733b60bc092c758930" ) );
	if ( DecryptedMessage == nullptr ) {
		LogSystem::Get( ).Log( xorstr_( "[605] Can't decrypt message!") );
	}

	std::this_thread::sleep_for( std::chrono::seconds( 1 ) );
	sendMessage( ConnectSocket , DecryptedMessage->c_str( ) );
	std::string NewMessage = Mem::Get( ).GenerateHash( *DecryptedMessage );
	StringCrypt::Get( ).CleanString( DecryptedMessage );


	//Allocate memory for the uncrypted message
	auto * FirstMessage = new std::string;
	FirstMessage->reserve( 32 ); // Pre-allocate memory

	//Wait for the message
	while ( FirstMessage->empty( ) ) {
		*FirstMessage = receiveMessage( ConnectSocket, 10);
	}



	this->CommunicationHash = xorstr_( "a477c5772e93d5a7f3f91d766d249e0a63b8bef5" );

	//Convert the message to hash, let`s check if it matches
	std::string ReceivedHash = Mem::Get( ).GenerateHash( FirstMessage->c_str( ) );

	//Free string memory
	StringCrypt::Get( ).CleanString( FirstMessage );

	if ( ReceivedHash != this->CommunicationHash ) {
		closeConnection( ConnectSocket );
		LogSystem::Get( ).Log( xorstr_( "[client][802] client hash mismatch!\n" ) );
	}

	Globals::Get( ).VerifiedSession = true;

	while ( m_running ) {

		std::this_thread::sleep_for( std::chrono::seconds( 5 ) );
		this->m_healthy = true;
		sendMessage( ConnectSocket , NewMessage.c_str( ) );
		NewMessage = Mem::Get( ).GenerateHash( NewMessage );
	
		// Recebe mensagem do cliente
		std::string Message = receiveMessage( ConnectSocket, 10 );
	
		if ( !Message.empty( ) ) {
			if ( Message != this->CommunicationHash ) {
				LogSystem::Get( ).Log( xorstr_( "[802] client hash mismatch!\n" ) );
			}
			else {	
				Utils::Get( ).WarnMessage( LIGHT_WHITE , xorstr_( "PING" ) , this->CommunicationHash , GRAY );
				this->CommunicationHash = Mem::Get( ).GenerateHash( this->CommunicationHash );
				UpdatePingTime( );
			}
		}
		else if ( !PingInTime( ) ) {
			LogSystem::Get( ).Log( xorstr_( "[client][303] Can`t find server answer!" ) );
		}
		this->m_healthy =true;
	}

	closeConnection( ConnectSocket );
}