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
		Utils::Get( ).WarnMessage( LIGHT_BLUE , xorstr_( "communication" ) , xorstr_( "Waiting detection thread" ) ,YELLOW );
	}
	else
		Utils::Get( ).WarnMessage( LIGHT_BLUE , xorstr_( "communication" ) , xorstr_( "Detection thread stopped" ) , GREEN );

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
		Utils::Get( ).WarnMessage( LIGHT_BLUE , xorstr_( "communication" ) , xorstr_( "can't convert ip address" ) , RED );
		closesocket( ListenSocket );
		WSACleanup( );
		return INVALID_SOCKET;
	}

	// Associa o socket com o endereço e porta
	iResult = bind( ListenSocket , ( SOCKADDR * ) &serverAddr , sizeof( serverAddr ) );
	if ( iResult == SOCKET_ERROR ) {
		Utils::Get( ).WarnMessage( LIGHT_BLUE , xorstr_( "communication" ) , xorstr_( "binding error" ) , RED );
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
		Utils::Get( ).WarnMessage( LIGHT_BLUE , xorstr_( "communication" ) , xorstr_( "can't listen client" ) , WHITE );
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

		Utils::Get( ).WarnMessage( LIGHT_BLUE , xorstr_( "communication" ) , xorstr_( "can't get server" ) , RED );
		return INVALID_SOCKET;
	}
	else if ( iResult == 0 ) {
		Utils::Get( ).WarnMessage( LIGHT_BLUE , xorstr_( "communication" ) , xorstr_( "connection time out" ) , RED );
		return INVALID_SOCKET;  // Timeout ocorreu
	}

	// Aceita a conexão do cliente
	SOCKET ClientSocket = accept( ListenSocket , NULL , NULL );
	if ( ClientSocket == INVALID_SOCKET ) {
		Utils::Get( ).WarnMessage( LIGHT_BLUE , xorstr_( "communication" ) , xorstr_( "can't accept connection" ) , RED );
		return INVALID_SOCKET;
	}

	return ClientSocket;
}

void Communication::sendMessage( SOCKET ClientSocket , const char * message ) {
	int iResult = send( ClientSocket , message , ( int ) strlen( message ) , 0 );
	if ( iResult == SOCKET_ERROR ) {
		Utils::Get( ).WarnMessage( LIGHT_BLUE , xorstr_( "communication" ) , xorstr_( "can't send message" ) , RED );
		LogSystem::Get( ).Log( xorstr_( "[105] Can't send message!" ) );
	}
}

std::string Communication::receiveMessage( SOCKET ClientSocket , int time ) {
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
		LogSystem::Get( ).Log( xorstr_( "[900] Connection closed" ) );
	}
	else {
		if ( WSAGetLastError( ) == WSAETIMEDOUT ) {
			LogSystem::Get( ).Log( xorstr_( "[902] Receive timeout" ) );
		}
		else {
			LogSystem::Get( ).Log( xorstr_( "[901] Can't receive message" ) );
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

void Communication::threadFunction( ) {
	
	Utils::Get( ).WarnMessage( LIGHT_BLUE , xorstr_( "communication" ) , xorstr_( "thread started sucessfully " ) , GREEN );

	ListenSocket = openConnection( xorstr_( "127.0.0.10" ) );
	if ( ListenSocket == INVALID_SOCKET ) {
		LogSystem::Get( ).Log( xorstr_( "[801] Can't open listener connection!" ) );
	}

	Utils::Get( ).WarnMessage( LIGHT_BLUE , xorstr_( "communication" ) , xorstr_( "waiting client connection..." ) , WHITE );

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

	if ( Injector::Get( ).Inject( xorstr_( "winsock.dll" ) , Globals::Get( ).ProtectProcess ) == 1 ) {
		Utils::Get( ).WarnMessage( LIGHT_BLUE , xorstr_( "communication" ) , xorstr_( "started client sucessfully" ) , WHITE );
	}
	else {
		LogSystem::Get( ).Log( xorstr_( "[0001] Can't init client!" ) );
	}

	SOCKET ClientSocket = listenForClient( ListenSocket , 10 );
	if ( ClientSocket == INVALID_SOCKET ) {
		closeconnection( ListenSocket );
		LogSystem::Get( ).Log( xorstr_( "[801] Can't open client connection!" ) );
	}

	Utils::Get( ).WarnMessage( LIGHT_BLUE , xorstr_( "communication" ) , xorstr_( "client connected sucessfully" ) , GREEN );

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
	}

	std::string * DecryptedMessage = StringCrypt::Get( ).DecryptString( xorstr_( "a477c5772e93d5a7f3f91d766d249e0a63b8bef5" ) );
	sendMessage( ClientSocket , DecryptedMessage->c_str( ) );
	std::string NewMessage = Mem::Get( ).GenerateHash( *DecryptedMessage );
	StringCrypt::Get( ).CleanString( DecryptedMessage );
	std::this_thread::sleep_for( std::chrono::seconds( 2 ) );


	Globals::Get( ).VerifiedSession = true;

	this->LastClientPing = now;

	while ( m_running ) {

		m_healthy = true;

		// Recebe mensagem do cliente
		std::string Message = receiveMessage( ClientSocket , 10 );

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
			if ( Mem::Get( ).IsPIDRunning( Globals::Get( ).ProtectProcess ) ) {
				HANDLE hProcess = Mem::Get( ).GetProcessHandle( Globals::Get( ).ProtectProcess );

				if ( hProcess != NULL ) {
					while ( ! TerminateProcess( hProcess , 0 ) ) {
						std::this_thread::sleep_for( std::chrono::milliseconds( 250 ) );
					}
				}

				LogSystem::Get( ).Log( xorstr_( "[303] Can`t find client answer!" ) );
			}
			else
				exit( 0 );
		}

		sendMessage( ClientSocket , NewMessage.c_str( ) );
		NewMessage = Mem::Get( ).GenerateHash( NewMessage );

		std::this_thread::sleep_for( std::chrono::seconds( 5 ) );
	}

	closeconnection( ClientSocket );
	closeconnection( ListenSocket );
}