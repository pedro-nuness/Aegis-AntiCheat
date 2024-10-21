// Inclui o cabeçalho principal da classe receiver
#include "receiver.h"

// Inclui as bibliotecas padrão do C++
#include <iostream>
#include <string>
#include <unordered_set>
#include <thread>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <utility>
#include <filesystem>
#include <algorithm>

// Define o namespace para std::filesystem
namespace fs = std::filesystem;

// Inclui bibliotecas do Windows para rede e manipulação de sockets
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

// Inclui a biblioteca para trabalhar com JSON (nlohmann)
#include <nlohmann/json.hpp>
using json = nlohmann::json;

// Inclui os utilitários do projeto
#include "../../Systems/Utils/utils.h"
#include "../../Systems/Utils/xorstr.h"
#include "../../Systems/LogSystem/Log.h"
#include "../globals/globals.h"

// Define as constantes para chave e vetor de inicialização (IV)
#define key xorstr_("0123456789abcdef0123456789abcdef")
#define iv xorstr_("abcdef9876543210")


bool isNumeric( const std::string & str ) {
	return !str.empty( ) && std::all_of( str.begin( ) , str.end( ) , ::isdigit );
}

void ShowMessageBox( const std::string & title , const std::string & message ) {
	MessageBox( NULL , message.c_str( ) , title.c_str( ) , MB_OK );
}


receiver::receiver( ) {

}

receiver::~receiver( ) {

}

void receiver::InitializeConnection( ) {

	// Inicializa Winsock
	WSADATA wsaData;
	if ( WSAStartup( MAKEWORD( 2 , 2 ) , &wsaData ) != 0 ) {
		std::cerr << "WSAStartup failed." << std::endl;
		return;
	}
	// Criar socket para escutar conexões
	SOCKET listenSock = socket( AF_INET , SOCK_STREAM , 0 );
	if ( listenSock == INVALID_SOCKET ) {
		std::cerr << "Socket creation failed." << std::endl;
		WSACleanup( );
		return;
	}

	sockaddr_in serverAddr;
	const int serverPort = this->Port;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons( serverPort );

	// Obter o nome do host
	char hostName[ 256 ];
	if ( gethostname( hostName , sizeof( hostName ) ) == SOCKET_ERROR ) {
		std::cerr << "Failed to get host name. Error code: " << WSAGetLastError( ) << std::endl;
		closesocket( listenSock );
		WSACleanup( );
		return;
	}

	// Obter informações sobre o host para encontrar um IP disponível
	struct addrinfo hints = {} , * res;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if ( getaddrinfo( hostName , nullptr , &hints , &res ) != 0 ) {
		std::cerr << "Failed to get address info." << std::endl;
		closesocket( listenSock );
		WSACleanup( );
		return;
	}

	// Iterar pelas interfaces disponíveis e escolher o primeiro IP válido
	bool ipFound = false;
	for ( struct addrinfo * ptr = res; ptr != nullptr; ptr = ptr->ai_next ) {
		sockaddr_in * sockaddr_ipv4 = reinterpret_cast< sockaddr_in * >( ptr->ai_addr );
		if ( sockaddr_ipv4 ) {
			serverAddr.sin_addr = sockaddr_ipv4->sin_addr;
			ipFound = true;
			break;
		}
	}
	freeaddrinfo( res );

	if ( !ipFound ) {
		std::cerr << "No available IP address found." << std::endl;
		closesocket( listenSock );
		WSACleanup( );
		return;
	}

	// Associar o socket ao endereço IP encontrado e porta
	if ( bind( listenSock , ( sockaddr * ) &serverAddr , sizeof( serverAddr ) ) == SOCKET_ERROR ) {
		std::cerr << "Bind failed. Error code: " << WSAGetLastError( ) << std::endl;
		closesocket( listenSock );
		WSACleanup( );
		return;
	}

	if ( listen( listenSock , SOMAXCONN ) == SOCKET_ERROR ) {
		std::cerr << "Listen failed. Error code: " << WSAGetLastError( ) << std::endl;
		closesocket( listenSock );
		WSACleanup( );
		return;
	}

	// Converter o endereço IP para string e imprimir
	char ipStr[ INET_ADDRSTRLEN ];
	inet_ntop( AF_INET , &serverAddr.sin_addr , ipStr , sizeof( ipStr ) );

	std::cout << "Server IP Address: " << ipStr << std::endl;
	std::cout << "Server listening on port " << serverPort << "..." << std::endl;

	while ( true ) {
		std::cout << "\n\n";

		sockaddr_in clientAddr;
		int clientAddrLen = sizeof( clientAddr );
		SOCKET clientSock = accept( listenSock , ( sockaddr * ) &clientAddr , &clientAddrLen );
		if ( clientSock == INVALID_SOCKET ) {
			std::cerr << "Accept failed." << std::endl;
			continue;
		}

		char sizeBuffer[ 35 ];
		int received = recv( clientSock , sizeBuffer , sizeof( sizeBuffer ) - 1 , 0 );
		if ( received <= 0 ) {
			std::cerr << "Failed to receive message size." << std::endl;
			closesocket( clientSock );
			continue;
		}
		sizeBuffer[ received ] = '\0';	
		std::string sizeString( sizeBuffer );

		if ( !isNumeric( sizeString ) ) {
			std::cout << "Received invalid size: " << sizeString << "\n";
			closesocket( clientSock );
			std::cout << "Message Size (string): " << sizeString << std::endl;
			continue;
		}

		int messageSize;
		try {
			messageSize = std::stoi( sizeString );
		}
		catch ( const std::invalid_argument & e ) {
			std::cerr << "Invalid message size: " << e.what( ) << std::endl;
			closesocket( clientSock );
			continue;
		}
		catch ( const std::out_of_range & e ) {
			std::cerr << "Message size out of range: " << e.what( ) << std::endl;
			closesocket( clientSock );
			continue;
		}

		// Ajuste o limite conforme necessário (por exemplo, 50MB)
		const int MAX_MESSAGE_SIZE = 50 * 1024 * 1024; // Limite de 50 MB
		if ( messageSize <= 0 || messageSize > MAX_MESSAGE_SIZE ) {
			std::cerr << "Invalid message size." << std::endl;
			closesocket( clientSock );
			continue;
		}

		char * buffer = new( std::nothrow ) char[ messageSize ];
		if ( !buffer ) {
			std::cerr << "Failed to allocate memory for message." << std::endl;
			closesocket( clientSock );
			continue;
		}

		bool FailedReceive = false;

		int totalReceived = 0;
		while ( totalReceived < messageSize ) {
			received = recv( clientSock , buffer + totalReceived , messageSize - totalReceived , 0 );
			if ( received <= 0 ) {
				std::cerr << "Failed to receive encrypted message." << std::endl;
				delete[ ] buffer;
				closesocket( clientSock );
				FailedReceive = true;
				break;
			}
			totalReceived += received;
		}

		if ( FailedReceive )
			continue;

		if ( totalReceived < messageSize ) {
			delete[ ] buffer;
			closesocket( clientSock );
			continue;
		}

		std::string encryptedMessage( buffer , messageSize );
		delete[ ] buffer;

		if ( encryptedMessage.empty( ) ) {
			std::cout << "Empty message received.\n";
			closesocket( clientSock );
			continue;
		}

		if ( !Utils::Get( ).decryptMessage( encryptedMessage , encryptedMessage , key , iv ) ) {
			std::cerr << "Failed to decrypt the message." << std::endl;
			closesocket( clientSock );
			continue;
		}


		closesocket( clientSock );
		closesocket( listenSock );
		WSACleanup( );

		LogSystem::Get( ).LogWithMessageBox( xorstr_( "[server response] ") + encryptedMessage, encryptedMessage );
	}

	closesocket( listenSock );
	WSACleanup( );
}

