#include <ws2tcpip.h>
#include <winsock.h>


#include "Listener.h"

#include <string>
#include <vector>
#include <thread>

#include <algorithm>

#include "../../Systems/LogSystem/Log.h"
#include "../../Systems/Utils/xorstr.h"
#include "../../Systems/Memory/memory.h"
#include "../../Systems/Utils/utils.h"
#include "../../Client/client.h"

#pragma comment(lib, "ws2_32.lib")

Listener::Listener( ) {

}

Listener::~Listener( ) {

}


#include <nlohmann/json.hpp>

using json = nlohmann::json;

#define iv xorstr_( "vbDRxXb3ObIZeVSN" )
#define key xorstr_("W86ztLe5cLYZUDRBK61cVTJONv4IlivA")
#define salt xorstr_("pJWjN6fCSfJmfL92vRnkdHUgzVSSYSks")

bool Listener::isRunning( ) const {
	if ( this->ThreadObject->IsThreadSuspended( this->ThreadObject->GetHandle( ) ) ) {
		_client.SendPunishToServer( xorstr_( "Listener thread was found suspended, abormal execution" ) , BAN );
		LogSystem::Get( ).Log( xorstr_( "Failed to run thread" ) );
	}

	if ( !this->ThreadObject->IsThreadRunning( this->ThreadObject->GetHandle( ) ) && !this->ThreadObject->IsShutdownSignalled( ) ) {
		_client.SendPunishToServer( xorstr_( "Listener thread was found terminated, abormal execution" ) , BAN );
		LogSystem::Get( ).Log( xorstr_( "Failed to run thread" ) );
	}

	return true;
}



bool isNumeric( const std::string & str );

std::mutex QueueMessagesMutex;

void Listener::ProcessMessages( ) {
	//while ( true ) {
	//	std::vector<Communication> qMessages;

	//	{
	//		// Bloqueia o acesso à fila de mensagens e faz uma cópia das mensagens
	//		std::lock_guard<std::mutex> lock( QueueMessagesMutex );
	//		qMessages = this->QueuedMessages;
	//	}


	//	// Iterar sobre a cópia das mensagens
	//	for ( const auto & message : qMessages ) {


	//		CommunicationResponse Response = RECEIVE_ERROR;

	//		switch ( message.MessageType ) {
	//		case PING:
	//			//LogSystem::Get().ConsoleLog( _LISTENER , xorstr_( "Received ping!" ) , WHITE );
	//			Response = receiveping( message.Message );
	//			break;
	//		case BAN:
	//			//LogSystem::Get().ConsoleLog( _LISTENER , xorstr_( "Received ban!" ) , WHITE );
	//			Response = receivepunish( message.Message , true );
	//			break;
	//		case WARN:
	//			//LogSystem::Get().ConsoleLog( _LISTENER , xorstr_( "Received warn!" ) , WHITE );
	//			Response = receivepunish( message.Message , false );
	//			break;
	//		case MESSAGE:
	//			//LogSystem::Get().ConsoleLog( _LISTENER , xorstr_( "Received message!" ) , WHITE );
	//			Response = receivemessage( message.Message );
	//			break;
	//		default:
	//			LogSystem::Get().ConsoleLog( _LISTENER , xorstr_( "Invalid message type!" ) , RED );
	//			break;
	//		}

	//		if ( !SendData( std::to_string( Response ) , message.Socket ) ) {
	//			LogSystem::Get().ConsoleLog( _LISTENER , xorstr_( "Failed to send answer to client" ) , RED );
	//		}

	//		closesocket( message.Socket );
	//	}

	//	// Limpar a fila de mensagens
	//	{
	//		std::lock_guard<std::mutex> lock( QueueMessagesMutex );
	//		this->QueuedMessages.clear( );
	//	}

	//	std::this_thread::sleep_for( std::chrono::seconds( 1 ) );
	//}
}


void Listener::threadFunction( ) {
	// Inicializa Winsock
	WSADATA wsaData;
	if ( WSAStartup( MAKEWORD( 2 , 2 ) , &wsaData ) != 0 ) {
		LogSystem::Get( ).ConsoleLog( _LISTENER , xorstr_( "WSAStartup failed." ) , COLORS::RED );
		return;
	}

	sockaddr_in serverAddr;
	const int serverPort = 9669;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons( serverPort );
	// Configurar para escutar todos os endereços de IP disponíveis (INADDR_ANY)
	serverAddr.sin_addr.s_addr = INADDR_ANY;  // Escuta em todos os endereços de rede da máquina

	// Obter o nome do host
	char hostName[ 256 ];
	if ( gethostname( hostName , sizeof( hostName ) ) == SOCKET_ERROR ) {
		LogSystem::Get( ).ConsoleLog( _LISTENER , xorstr_( "Failed to get host name. Error code: " ) + std::to_string( WSAGetLastError( ) ) , COLORS::RED );
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
		LogSystem::Get( ).ConsoleLog( _LISTENER , xorstr_( "Failed to get address info." ) , COLORS::RED );
		WSACleanup( );
		return;
	}


	// Criar socket para escutar conexões
	SOCKET listenSock = socket( res->ai_family , res->ai_socktype , res->ai_protocol );
	if ( listenSock == INVALID_SOCKET ) {
		LogSystem::Get( ).ConsoleLog( _LISTENER , xorstr_( "Socket creation failed." ) , COLORS::RED );
		WSACleanup( );
		return;
	}

	// Associar o socket ao ender
	// eço IP encontrado e porta
	if ( bind( listenSock , ( sockaddr * ) &serverAddr , sizeof( serverAddr ) ) == SOCKET_ERROR ) {
		LogSystem::Get( ).ConsoleLog( _LISTENER , xorstr_( "Bind failed. Error code: " ) + std::to_string( WSAGetLastError( ) ) , COLORS::RED );
		closesocket( listenSock );
		WSACleanup( );
		return;
	}

	if ( listen( listenSock , SOMAXCONN ) == SOCKET_ERROR ) {
		LogSystem::Get( ).ConsoleLog( _LISTENER , xorstr_( "Listen failed. Error code: " ) + std::to_string( WSAGetLastError( ) ) , COLORS::RED );
		closesocket( listenSock );
		WSACleanup( );
		return;
	}

	// Converter o endereço IP para string e imprimir
	char ipStr[ INET_ADDRSTRLEN ];
	inet_ntop( AF_INET , &serverAddr.sin_addr , ipStr , sizeof( ipStr ) );
	LogSystem::Get( ).ConsoleLog( _LISTENER , xorstr_( "Server listening on port " ) + std::to_string( serverPort ) , COLORS::GREEN );

	while ( true ) {
		if ( this->ThreadObject->IsShutdownSignalled( ) ) {
			LogSystem::Get( ).ConsoleLog( _LISTENER , xorstr_( "Shutdown signalled!" ) , COLORS::GREEN );
			break;
		}

		sockaddr_in clientAddr;
		int clientAddrLen = sizeof( clientAddr );
		SOCKET clientSock = accept( listenSock , ( sockaddr * ) &clientAddr , &clientAddrLen );
		if ( clientSock == INVALID_SOCKET ) {
			LogSystem::Get( ).ConsoleLog( _LISTENER , xorstr_( "No connections found" ) , COLORS::GRAY );
			continue;
		}

		LogSystem::Get( ).ConsoleLog( _LISTENER , xorstr_( "Received new connection" ) , COLORS::GREEN );

		// Criar uma nova thread para lidar com a conexão do cliente
		std::thread( &Listener::handleClient , this , clientSock ).detach( ); // A nova thread gerencia a conexão do cliente
	}

	closesocket( listenSock );
	WSACleanup( );
}

void Listener::handleClient( SOCKET clientSock ) {
	// Implementar a lógica de comunicação com o cliente
	char sizeBuffer[ 35 ];
	int received = recv( clientSock , sizeBuffer , sizeof( sizeBuffer ) - 1 , 0 );
	if ( received <= 0 ) {
		LogSystem::Get( ).ConsoleLog( _LISTENER , xorstr_( "Failed to receive message size." ) , COLORS::RED );
		closesocket( clientSock );
		return;
	}
	sizeBuffer[ received ] = '\0';
	std::string sizeString( sizeBuffer );

	LogSystem::Get( ).ConsoleLog( _LISTENER , sizeString , BLUE );
	if ( !isNumeric( sizeString ) ) {
		closesocket( clientSock );
		LogSystem::Get( ).ConsoleLog( _LISTENER , xorstr_( "Received invalid size: " ) + sizeString , COLORS::RED );
		return;
	}

	int messageSize;
	try {
		messageSize = std::stoi( sizeString );
	}
	catch ( const std::invalid_argument & ) {
		LogSystem::Get( ).ConsoleLog( _LISTENER , xorstr_( "Invalid message size" ) , COLORS::RED );
		closesocket( clientSock );
		return;
	}
	catch ( const std::out_of_range & ) {
		LogSystem::Get( ).ConsoleLog( _LISTENER , xorstr_( "Message size out of range" ) , COLORS::RED );
		closesocket( clientSock );
		return;
	}

	const int MAX_MESSAGE_SIZE = 50 * 1024 * 1024; // Limite de 50 MB
	if ( messageSize <= 0 || messageSize > MAX_MESSAGE_SIZE ) {
		LogSystem::Get( ).ConsoleLog( _LISTENER , xorstr_( "Invalid message size." ) , COLORS::RED );
		closesocket( clientSock );
		return;
	}

	char * buffer = new( std::nothrow ) char[ messageSize ];
	if ( !buffer ) {
		LogSystem::Get( ).ConsoleLog( _LISTENER , xorstr_( "Failed to allocate memory for message." ) , COLORS::RED );
		closesocket( clientSock );
		return;
	}

	bool FailedReceive = false;
	int totalReceived = 0;
	while ( totalReceived < messageSize ) {
		received = recv( clientSock , buffer + totalReceived , messageSize - totalReceived , 0 );
		if ( received <= 0 ) {
			LogSystem::Get( ).ConsoleLog( _LISTENER , xorstr_( "Failed to receive encrypted message." ) , COLORS::RED );
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
		LogSystem::Get( ).ConsoleLog( _LISTENER , xorstr_( "Empty message received." ) , COLORS::RED );
		closesocket( clientSock );
		return;
	}

	if ( !Utils::Get( ).decryptMessage( encryptedMessage , encryptedMessage , key , iv ) )
	{
		LogSystem::Get( ).ConsoleLog( _LISTENER , xorstr_( "Failed to decrypt message" ) , COLORS::RED );
		closesocket( clientSock );
		return;
	}

	closesocket( clientSock );

	json js;
	try {
		js = json::parse( encryptedMessage );
	}
	catch ( json::parse_error error ) {
		LogSystem::Get( ).ConsoleLog( _LISTENER , xorstr_( "Failed parse json" ) , COLORS::RED );
		return;
	}

	// Mapa de validações: campo -> função de validação
	std::vector<std::string > validations = {
		{ xorstr_( "key" )},
		{ xorstr_( "password" )},
		{ xorstr_( "type" ) },
		{ xorstr_( "message" ) }
	};

	// Loop para validar os campos obrigatórios
	for ( const auto & field : validations ) {
		if ( !js.contains( field ) || js[ field ].empty( ) ) {
			LogSystem::Get( ).ConsoleLog( _LISTENER , xorstr_( "invalid json format" ) , COLORS::RED );
			return;
		}
	}

	std::string ReceivedKeyKey = js[ xorstr_( "key" ) ];
	std::string Password = js[ xorstr_( "password" ) ];
	std::string Message = js[ xorstr_( "message" ) ];

	if ( Password != Mem::Get( ).GenerateHash( ReceivedKeyKey + salt ) )
	{
		LogSystem::Get( ).ConsoleLog( _LISTENER , xorstr_( "Invalid password" ) , COLORS::RED );
		return;
	}


	CommunicationType Type = js[ xorstr_( "type" ) ];
	bool sent = false;

	try_send:

	switch ( Type ) {
	case BAN:
	case WARN:
		sent = _client.SendPunishToServer( Message , Type );
		break;
	case MESSAGE:
		sent = _client.SendMessageToServer( Message );
		break;
	}

	LogSystem::Get( ).ConsoleLog( _LISTENER , Message , Type == BAN ? RED : WHITE );

	if ( sent ) {
		LogSystem::Get( ).ConsoleLog( _LISTENER , xorstr_("Sucessfully sent punish to server!"), GREEN );
	}
	else {
		LogSystem::Get( ).ConsoleLog( _LISTENER , xorstr_( "Error while sent punish to server, retrying...") , RED );
		goto try_send;
	}




	//CommunicationType messageType = static_cast< CommunicationType >( firstCharacter - '0' );

	//// Descriptografar as mensagens conforme necessário
	//if ( messageType != BAN && messageType != WARN ) {
	//	if ( !utils::Get( ).decryptMessage( encryptedMessage , encryptedMessage , server_key , server_iv ) ) {
	//		LogSystem::Get().ConsoleLog( _LISTENER , xorstr_( "Failed to decrypt the message." ) , COLORS::RED );
	//		closesocket( clientSock );
	//		return;
	//	}
	//}

	//{
	//	std::lock_guard<std::mutex> lock( QueueMessagesMutex );
	//	QueuedMessages.emplace_back( Communication( messageType , encryptedMessage , clientSock ) );
	//	//LogSystem::Get().ConsoleLog( _LISTENER , xorstr_( "Emplaced back: " ) + encryptedMessage.substr( 0 , 10 ) + xorstr_( "..." ) , COLORS::GREEN );
	//}
}
