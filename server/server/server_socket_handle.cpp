#include <winsock2.h>
#include <ws2tcpip.h>
#include <comdef.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_set>
#include <utility>

#include <dpp/colors.h>
#include <nlohmann/json.hpp>

#include "server.h"
#include "../config/config.h"
#include "../globals/globals.h"
#include "../image/image.h"
#include "../memory/memory.h"
#include "../utils/utils.h"
#include "../utils/File/File.h"
#include "../webhook/webhook.h"

#pragma comment(lib, "ws2_32.lib")

namespace fs = std::filesystem;
using json = nlohmann::json;

bool isNumeric( const std::string & str ) {
	return !str.empty( ) && std::all_of( str.begin( ) , str.end( ) , ::isdigit );
}

std::mutex QueueMessagesMutex;


void Server::ProcessMessages( ) {
	while ( true ) {

		std::vector<Communication> qMessages;

		{
			// Bloqueia o acesso à fila de mensagens e faz uma cópia das mensagens
			std::lock_guard<std::mutex> lock( QueueMessagesMutex );
			qMessages = this->QueuedMessages;
		}

		// Iterar sobre a cópia das mensagens
		for ( const auto & message : qMessages ) {

			CommunicationResponse Response = RECEIVE_ERROR;

			std::string Ip;

			switch ( message.MessageType ) {
			case CommunicationType::PING:
				//utils::Get( ).WarnMessage( _SERVER , xorstr_( "Received ping!" ) , WHITE );
				Response = receiveping( message.Message , &Ip );
				break;
			case  CommunicationType::BAN:
				//utils::Get( ).WarnMessage( _SERVER , xorstr_( "Received ban!" ) , WHITE );
				Response = receivepunish( message.Message , BAN );
				break;
			case  CommunicationType::WARN:
				//utils::Get( ).WarnMessage( _SERVER , xorstr_( "Received warn!" ) , WHITE );
				Response = receivepunish( message.Message , WARN );
				break;
			case  CommunicationType::SCREENSHOT:
				Response = receivepunish( message.Message , SCREENSHOT );
				break;
			case  CommunicationType::MESSAGE:
				//utils::Get( ).WarnMessage( _SERVER , xorstr_( "Received message!" ) , WHITE );
				Response = receivemessage( message.Message );
				break;
			default:
				utils::Get( ).WarnMessage( _SERVER , xorstr_( "Invalid message type!" ) , RED );
				break;
			}

			json ResponseJson;
			ResponseJson[ xorstr_( "response" ) ] = Response;
			if ( Response == RECEIVE_LOGGEDIN ) {
				std::lock_guard<std::mutex> lock( connectionMutex );
				if ( _globals.ConnectionMap.find( Ip ) != _globals.ConnectionMap.end( ) ) {
					ResponseJson[ xorstr_( "sessionid" ) ] = _globals.ConnectionMap[ Ip ].GetSessionID( );
				}
				else {
					utils::Get( ).WarnMessage( _SERVER , xorstr_( "Unexpected error, tried to get session id of a not connected player!" ) , RED );
				}
			}

			if ( !SendData( ResponseJson.dump( ) , message.Socket ) ) {
				utils::Get( ).WarnMessage( _SERVER , xorstr_( "Failed to send answer to client" ) , RED );
			}
			else if ( !Ip.empty( ) ) {
				std::lock_guard<std::mutex> lock( connectionMutex );
				_globals.ConnectionMap[ Ip ].UpdateIVCode( );
			}

			closesocket( message.Socket );
		}

		// Limpar a fila de mensagens
		{
			std::lock_guard<std::mutex> lock( QueueMessagesMutex );
			this->QueuedMessages.clear( );
		}

		std::this_thread::sleep_for( std::chrono::seconds( 1 ) );
	}
}



void Server::threadfunction( ) {
	// Inicializa Winsock
	WSADATA wsaData;
	if ( WSAStartup( MAKEWORD( 2 , 2 ) , &wsaData ) != 0 ) {
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "WSAStartup failed." ) , COLORS::RED );
		return;
	}

	LoadBlockedSet( ); // Carrega os conjuntos bloqueados ao iniciar o servidor



	sockaddr_in serverAddr;
	const int serverPort = 2452;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons( serverPort );
	// Configurar para escutar todos os endereços de IP disponíveis (INADDR_ANY)
	serverAddr.sin_addr.s_addr = INADDR_ANY;  // Escuta em todos os endereços de rede da máquina

	// Obter o nome do host
	char hostName[ 256 ];
	if ( gethostname( hostName , sizeof( hostName ) ) == SOCKET_ERROR ) {
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Failed to get host name. Error code: " ) + std::to_string( WSAGetLastError( ) ) , COLORS::RED );
		WSACleanup( );
		return;
	}

	// Obter informações sobre o host para encontrar um IP disponível
	struct addrinfo hints = {} , * res;
	hints.ai_family = AF_INET;        // IPv4
	hints.ai_socktype = SOCK_STREAM;  // TCP
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;      // Configura o socket para escutar


	if ( getaddrinfo( hostName , nullptr , &hints , &res ) != 0 ) {
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Failed to get address info." ) , COLORS::RED );
		WSACleanup( );
		return;
	}


	// Criar socket para escutar conexões
	SOCKET listenSock = socket( res->ai_family , res->ai_socktype , res->ai_protocol );
	if ( listenSock == INVALID_SOCKET ) {
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Socket creation failed." ) , COLORS::RED );
		WSACleanup( );
		return;
	}

	// Associar o socket ao ender
	// eço IP encontrado e porta
	if ( bind( listenSock , ( sockaddr * ) &serverAddr , sizeof( serverAddr ) ) == SOCKET_ERROR ) {
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Bind failed. Error code: " ) + std::to_string( WSAGetLastError( ) ) , COLORS::RED );
		closesocket( listenSock );
		WSACleanup( );
		return;
	}

	if ( listen( listenSock , SOMAXCONN ) == SOCKET_ERROR ) {
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Listen failed. Error code: " ) + std::to_string( WSAGetLastError( ) ) , COLORS::RED );
		closesocket( listenSock );
		WSACleanup( );
		return;
	}

	// Converter o endereço IP para string e imprimir
	char ipStr[ INET_ADDRSTRLEN ];
	inet_ntop( AF_INET , &serverAddr.sin_addr , ipStr , sizeof( ipStr ) );
	_globals.SelfIP = ipStr;
	utils::Get( ).WarnMessage( _SERVER , xorstr_( "Server listening on port " ) + std::to_string( serverPort ) , COLORS::GREEN );

	_globals.ServerOpen = true;

	std::thread( &Server::validateconnections , this ).detach( );
	std::thread( &Server::ProcessMessages , this ).detach( );

	while ( true ) {
		sockaddr_in clientAddr;
		int clientAddrLen = sizeof( clientAddr );
		SOCKET clientSock = accept( listenSock , ( sockaddr * ) &clientAddr , &clientAddrLen );
		if ( clientSock == INVALID_SOCKET ) {
			utils::Get( ).WarnMessage( _SERVER , xorstr_( "Accept failed." ) , COLORS::RED );
			continue;
		}

		//utils::Get( ).WarnMessage( _SERVER , xorstr_( "Received new connection" ) , COLORS::GREEN );

		// Criar uma nova thread para lidar com a conexão do cliente
		std::thread( &Server::handleClient , this , clientSock ).detach( ); // A nova thread gerencia a conexão do cliente
	}

	closesocket( listenSock );
	WSACleanup( );
}

void Server::handleClient( SOCKET clientSock ) {
	// Implementar a lógica de comunicação com o cliente
	char sizeBuffer[ 35 ];
	int received = recv( clientSock , sizeBuffer , sizeof( sizeBuffer ) - 1 , 0 );
	if ( received <= 0 ) {
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Failed to receive message size." ) , COLORS::RED );
		closesocket( clientSock );
		return;
	}
	sizeBuffer[ received ] = '\0';
	std::string sizeString( sizeBuffer );


	if ( !isNumeric( sizeString ) ) {
		closesocket( clientSock );
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Received invalid size: " ) + sizeString , COLORS::RED );
		return;
	}

	int messageSize;
	try {
		messageSize = std::stoi( sizeString );
	}
	catch ( const std::invalid_argument & ) {
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Invalid message size" ) , COLORS::RED );
		closesocket( clientSock );
		return;
	}
	catch ( const std::out_of_range & ) {
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Message size out of range" ) , COLORS::RED );
		closesocket( clientSock );
		return;
	}

	const int MAX_MESSAGE_SIZE = 50 * 1024 * 1024; // Limite de 50 MB
	if ( messageSize <= 0 || messageSize > MAX_MESSAGE_SIZE ) {
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Invalid message size." ) , COLORS::RED );
		closesocket( clientSock );
		return;
	}

	char * buffer = new( std::nothrow ) char[ messageSize ];
	if ( !buffer ) {
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Failed to allocate memory for message." ) , COLORS::RED );
		closesocket( clientSock );
		return;
	}

	bool FailedReceive = false;
	int totalReceived = 0;
	while ( totalReceived < messageSize ) {
		received = recv( clientSock , buffer + totalReceived , messageSize - totalReceived , 0 );
		if ( received <= 0 ) {
			utils::Get( ).WarnMessage( _SERVER , xorstr_( "Failed to receive encrypted message." ) , COLORS::RED );
			delete[ ] buffer;
			closesocket( clientSock );
			FailedReceive = true;
			break;
		}
		totalReceived += received;
	}

	if ( FailedReceive ) {
		return;
	}

	if ( totalReceived < messageSize ) {
		delete[ ] buffer;
		closesocket( clientSock );
		return;
	}

	std::string encryptedMessage( buffer , messageSize );
	delete[ ] buffer;

	if ( encryptedMessage.empty( ) ) {
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Empty message received." ) , COLORS::RED );
		closesocket( clientSock );
		return;
	}

	char firstCharacter = encryptedMessage[ 0 ];
	encryptedMessage = encryptedMessage.substr( 1 );

	if ( !isdigit( firstCharacter ) ) {
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Invalid message type: " ) + firstCharacter , COLORS::RED );
		closesocket( clientSock );
		return;
	}

	CommunicationType messageType = static_cast< CommunicationType >( firstCharacter - '0' );


	bool Decrypt = true;

	switch ( messageType ) {
	case BAN:
	case WARN:
	case SCREENSHOT:
		Decrypt = false;
		break;
	}


	// Descriptografar as mensagens conforme necessário
	if ( Decrypt ) {
		if ( !utils::Get( ).decryptMessage( encryptedMessage , encryptedMessage , server_key , server_iv ) ) {
			utils::Get( ).WarnMessage( _SERVER , xorstr_( "Failed to decrypt the message." ) , COLORS::RED );
			closesocket( clientSock );
			return;
		}
	}

	{
		std::lock_guard<std::mutex> lock( QueueMessagesMutex );
		QueuedMessages.emplace_back( Communication( messageType , encryptedMessage , clientSock ) );
		//utils::Get( ).WarnMessage( _SERVER , xorstr_( "Emplaced back: " ) + encryptedMessage.substr( 0 , 10 ) + xorstr_( "..." ) , COLORS::GREEN );
	}
}


bool Server::SendData( std::string data , SOCKET socket ) {
	if ( socket == INVALID_SOCKET ) {
		//LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Invalid socket." ) , RED );
		return false;
	}

	std::string encryptedMessage;

	encryptedMessage = data;

	if ( !utils::Get( ).encryptMessage( encryptedMessage , encryptedMessage , server_key , server_iv ) ) {
		return false;
	}

	long int messageSize = encryptedMessage.size( );

	std::string messageSizeStr = std::to_string( messageSize );
	int SizeBackup = messageSizeStr.size( );
	//message_size bufer = char * 35 - 1 ( end of the string \0 )
	messageSizeStr.insert( 0 , 34 - SizeBackup , '0' );  // Insere 'quantidade_zeros' zeros no início
	// 000000..001348
	if ( send( socket , messageSizeStr.c_str( ) , messageSizeStr.size( ) , 0 ) == SOCKET_ERROR ) {
		//LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Failed to send message size." ) , RED );
		return false;
	}

	//pause, so the server can process it
	std::this_thread::sleep_for( std::chrono::milliseconds( 50 ) );

	int totalSent = 0;
	while ( totalSent < messageSize ) {
		int sent = send( socket , encryptedMessage.c_str( ) + totalSent , messageSize - totalSent , 0 );
		if ( sent == SOCKET_ERROR ) {
			//LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Failed to send encrypted message." ) , RED );
			closesocket( socket );
			WSACleanup( );
			return false;
		}
		totalSent += sent;
	}

	//LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Message sent successfully." ) , GREEN );
	return true;
}
