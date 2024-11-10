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
#include "client.h"

// Define as constantes para chave e vetor de inicialização (IV)
#define key xorstr_("ib33o5m8zsqlcgys3w46cfmtn8ztg1kn")
#define iv xorstr_("ume9ugz3m7lgch1z")


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

enum REQUEST_TYPE {
	SCREENSHOT ,
	BAN_REQUEST
};

void receiver::ProcessJson( std::string Json ) {
	json js;
	try {
		js = json::parse( Json );
	}
	catch ( const json::parse_error & e ) {
		Utils::Get( ).WarnMessage( _SERVER_MESSAGE , xorstr_( "Failed to convert message to json!" ) , RED );
		return;
	}

	const std::vector<std::string> requiredFields = {
		xorstr_( "request_type" ),
		xorstr_( "message" )
	};

	for ( const auto & field : requiredFields ) {
		if ( !js.contains( field ) || js[ field ].empty( ) ) {
			Utils::Get( ).WarnMessage( _SERVER_MESSAGE , xorstr_( "Can't get " ) + field + xorstr_( "!" ) , RED );
			return;
		}
	}

	REQUEST_TYPE Request = ( REQUEST_TYPE ) js[ xorstr_( "request_type" ) ];

	switch ( Request ) {
	case SCREENSHOT:
		client::Get( ).SendPunishToServer( js[ xorstr_( "message" ) ] , false );
		break;
	case BAN_REQUEST:
		client::Get( ).SendPunishToServer( js[ xorstr_( "message" ) ] , true );
		break;
	default:
		Utils::Get( ).WarnMessage( _SERVER_MESSAGE , xorstr_( "Invalid parameters" ) , RED );
		break;
	}
}

void receiver::InitializeConnection( ) {

	// Inicializa Winsock
	WSADATA wsaData;
	if ( WSAStartup( MAKEWORD( 2 , 2 ) , &wsaData ) != 0 ) {
		LogSystem::Get( ).Log( xorstr_( "WSAStartup failed." ) );
		return;
	}
	// Criar socket para escutar conexões
	SOCKET listenSock = socket( AF_INET , SOCK_STREAM , 0 );
	if ( listenSock == INVALID_SOCKET ) {	
		WSACleanup( );
		LogSystem::Get( ).Log( xorstr_( "Socket creation failed." ) );
		return;
	}

	sockaddr_in serverAddr;
	const int serverPort = this->Port;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons( serverPort );

	// Obter o nome do host
	char hostName[ 256 ];
	if ( gethostname( hostName , sizeof( hostName ) ) == SOCKET_ERROR ) {
		closesocket( listenSock );
		WSACleanup( );
		LogSystem::Get( ).Log( xorstr_( "Failed to get host name. Error code: " ) + std::to_string( WSAGetLastError( ) ) );
		return;
	}

	// Obter informações sobre o host para encontrar um IP disponível
	struct addrinfo hints = {} , * res;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if ( getaddrinfo( hostName , nullptr , &hints , &res ) != 0 ) {
		closesocket( listenSock );
		WSACleanup( );
		LogSystem::Get( ).Log( xorstr_( "Failed to get address info." ) );
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
		closesocket( listenSock );
		WSACleanup( );
		LogSystem::Get( ).Log( xorstr_( "No available IP address found." ) );
		return;
	}

	// Associar o socket ao endereço IP encontrado e porta
	if ( bind( listenSock , ( sockaddr * ) &serverAddr , sizeof( serverAddr ) ) == SOCKET_ERROR ) {
		closesocket( listenSock );
		WSACleanup( );
		LogSystem::Get( ).Log( xorstr_( "Bind failed. Error code: " ) + std::to_string( WSAGetLastError( ) ) );
		return;
	}

	if ( listen( listenSock , SOMAXCONN ) == SOCKET_ERROR ) {
		closesocket( listenSock );
		WSACleanup( );
		LogSystem::Get( ).Log( xorstr_( "Listen failed. Error code: " ) + std::to_string( WSAGetLastError( ) ) );
		return;
	}

	// Converter o endereço IP para string e imprimir
	char ipStr[ INET_ADDRSTRLEN ];
	inet_ntop( AF_INET , &serverAddr.sin_addr , ipStr , sizeof( ipStr ) );

	Utils::Get().WarnMessage(_SERVER, xorstr_("Server IP Address: ") + std::string(ipStr)+ xorstr_( ":" ) +  std::to_string( serverPort ) , GREEN );

	while ( true ) {

		if ( this->IsShutdownSignalled( ) ) {
			return;
		}

		sockaddr_in clientAddr;
		int clientAddrLen = sizeof( clientAddr );
		SOCKET clientSock = accept( listenSock , ( sockaddr * ) &clientAddr , &clientAddrLen );
		if ( clientSock == INVALID_SOCKET ) {
			break;
		}

		char sizeBuffer[ 35 ];
		int received = recv( clientSock , sizeBuffer , sizeof( sizeBuffer ) - 1 , 0 );
		if ( received <= 0 ) {
			Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Failed to receive message size." ) , RED );
			closesocket( clientSock );
			continue;
		}
		sizeBuffer[ received ] = '\0';
		std::string sizeString( sizeBuffer );

		if ( !isNumeric( sizeString ) ) {
			Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Received invalid size" ) , RED );
			closesocket( clientSock );
			continue;
		}

		int messageSize;
		try {
			messageSize = std::stoi( sizeString );
		}
		catch ( const std::invalid_argument & e ) {
			closesocket( clientSock );
			continue;
		}
		catch ( const std::out_of_range & e ) {
			Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Message out of range" ) , RED );
			closesocket( clientSock );
			continue;
		}

		// Ajuste o limite conforme necessário (por exemplo, 50MB)
		const int MAX_MESSAGE_SIZE = 50 * 1024 * 1024; // Limite de 50 MB
		if ( messageSize <= 0 || messageSize > MAX_MESSAGE_SIZE ) {
			closesocket( clientSock );
			continue;
		}

		char * buffer = new( std::nothrow ) char[ messageSize ];
		if ( !buffer ) {
			Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Failed to allocate process memory" ) , RED );
			closesocket( clientSock );
			continue;
		}

		bool FailedReceive = false;

		int totalReceived = 0;
		while ( totalReceived < messageSize ) {
			received = recv( clientSock , buffer + totalReceived , messageSize - totalReceived , 0 );
			if ( received <= 0 ) {
				Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Failed to receive encrypted message" ) , RED );
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
			Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Received empty message" ) , RED );
			closesocket( clientSock );
			continue;
		}

		if ( !Utils::Get( ).decryptMessage( encryptedMessage , encryptedMessage , key , iv ) ) {
			Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Failed to decrypt message" ) , RED );
			closesocket( clientSock );
			continue;
		}

		json js;

		try {
			js = json::parse( encryptedMessage );
		}
		catch ( const json::parse_error & e ) {
			closesocket( clientSock );
			closesocket( listenSock );
			WSACleanup( );
			LogSystem::Get( ).LogWithMessageBox( xorstr_( "[server response] " ) + encryptedMessage , encryptedMessage );
			break;
		}

		// It's a json message, let's process it
		ProcessJson( js.dump( ) );
	}

	closesocket( listenSock );
	WSACleanup( );
}

