#include <iostream>

#include <winsock2.h>
#include <ws2tcpip.h>


#include "Communication.h"

#include "../../Globals/Globals.h"
#include "../../Systems/Memory/memory.h"
#include "../../Systems/LogSystem/Log.h"
#include "../../Systems/Utils/crypt_str.h"
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
		std::cout << crypt_str( "[communication THREAD] Waiting detection thread!\n");
	}
	else
		std::cout << crypt_str( "[communication THREAD] Detection thread was terminated!\n");

	start( );
}

void Communication::requestupdate( ) {
	this->m_healthy = false;
}

SOCKET Communication::openconnection( ) {
	WSADATA wsaData;
	int iResult;

	// Inicializa Winsock
	iResult = WSAStartup( MAKEWORD( 2 , 2 ) , &wsaData );
	if ( iResult != 0 ) {
		std::cout << crypt_str( "WSAStartup falhou: ") << iResult << std::endl;
		return INVALID_SOCKET;
	}

	// Cria o socket do servidor
	SOCKET ListenSocket = socket( AF_INET , SOCK_STREAM , IPPROTO_TCP );
	if ( ListenSocket == INVALID_SOCKET ) {
		std::cout << crypt_str( "Erro ao criar socket: ") << WSAGetLastError( ) << std::endl;
		WSACleanup( );
		return INVALID_SOCKET;
	}

	// Define o endereço e porta
	sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_addr.s_addr = INADDR_ANY;
	serverAddr.sin_port = htons( 8080 );

	// Associa o socket com o endereço e porta
	iResult = bind( ListenSocket , ( SOCKADDR * ) &serverAddr , sizeof( serverAddr ) );
	if ( iResult == SOCKET_ERROR ) {
		std::cout << crypt_str( "Erro ao fazer bind: ") << WSAGetLastError( ) << std::endl;
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
		std::cout << crypt_str( "Erro ao ouvir: ") << WSAGetLastError( ) << std::endl;
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
		std::cout << crypt_str( "Erro no select: ") << WSAGetLastError( ) << std::endl;
		return INVALID_SOCKET;
	}
	else if ( iResult == 0 ) {
		std::cout << crypt_str( "Tempo de conexão expirado (timeout).") << std::endl;
		return INVALID_SOCKET;  // Timeout ocorreu
	}

	// Aceita a conexão do cliente
	SOCKET ClientSocket = accept( ListenSocket , NULL , NULL );
	if ( ClientSocket == INVALID_SOCKET ) {
		std::cout << crypt_str( "Erro ao aceitar conexão: ") << WSAGetLastError( ) << std::endl;
		return INVALID_SOCKET;
	}

	return ClientSocket;
}

void Communication::sendMessage( SOCKET ClientSocket , const char * message ) {
	int iResult = send( ClientSocket , message , ( int ) strlen( message ) , 0 );
	if ( iResult == SOCKET_ERROR ) {
		std::cout << crypt_str( "Erro ao enviar mensagem: ") << WSAGetLastError( ) << std::endl;
	}
}

std::string Communication::receiveMessage( SOCKET ClientSocket ) {
	char recvbuf[ 512 ];
	int iResult = recv( ClientSocket , recvbuf , 512 , 0 );
	if ( iResult > 0 ) {
		recvbuf[ iResult ] = '\0'; // Garante que a string recebida seja terminada por nulo
		std::string response = std::string( recvbuf );
		RtlZeroMemory( recvbuf , sizeof( recvbuf ) );
		return response;
	}
	else if ( iResult == 0 ) {
		std::cout << crypt_str( "Conexão fechada pelo cliente.") << std::endl;
		LogSystem::Get( ).Log( crypt_str( "[SERVER][900] Connection closed" ) );
	}
	else {
		std::cout << crypt_str( "Erro ao receber mensagem: ") << WSAGetLastError( ) << std::endl;
		LogSystem::Get( ).Log( crypt_str( "[SERVER][901] Can't receive message" ) );
	}
	return "";
}


void Communication::threadFunction( ) {

	

	std::cout << crypt_str( "[communication] thread started sucessfully!\n" );

	ListenSocket = openconnection( );
	if ( ListenSocket == INVALID_SOCKET ) {
		LogSystem::Get( ).Log( crypt_str( "[801] Can't open listener connection!" ) );
	}

	std::cout << crypt_str("[communication] waiting client connection...") << std::endl;

	SOCKET ClientSocket = listenForClient( ListenSocket, 5);
	if ( ClientSocket == INVALID_SOCKET ) {
		closeconnection( ListenSocket );
		LogSystem::Get( ).Log( crypt_str( "[801] Can't open client connection!" ) );
	}

	std::cout << crypt_str("[communication] client connected sucessfully") << std::endl;

	this->CommunicationHash = crypt_str( "90ed071b4c6ba84ada3b57733b60bc092c758930" );
	
	std::string FirstMessage = "";
	while ( FirstMessage.empty() ) {
		FirstMessage.clear( );
		FirstMessage = receiveMessage(ClientSocket);
	}
	std::string ReceivedHash = Mem::Get( ).GenerateHash( FirstMessage );
	std::cout << FirstMessage << "\n";
	if ( ReceivedHash != this->CommunicationHash ) {
		closeconnection( ListenSocket );
		LogSystem::Get( ).Log( crypt_str( "[802] client hash mismatch!\n" ) );
	}

	Globals::Get( ).VerifiedSession = true;

	while ( m_running ) {

		m_healthy = true;

		// Recebe mensagem do cliente
		std::string Message = receiveMessage( ClientSocket );

		if ( !Message.empty() && Message != this->CommunicationHash ) {
			LogSystem::Get( ).Log( crypt_str( "[802] client hash mismatch!\n" ) );
		}
		else if ( Message == this->CommunicationHash ) {
			this->CommunicationHash = Mem::Get( ).GenerateHash( this->CommunicationHash );
			std::cout << crypt_str( "[client ping] " ) << Message << std::endl;
		}

		// Envia mensagem para o cliente
		sendMessage( ClientSocket , "Hello from server" );

		std::this_thread::sleep_for(std::chrono::seconds( 2 ) );
	}

	closeconnection( ClientSocket );
	closeconnection( ListenSocket );
}