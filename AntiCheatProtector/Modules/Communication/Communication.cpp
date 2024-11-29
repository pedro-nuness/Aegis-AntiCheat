#include <iostream>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <algorithm>

#include "Communication.h"
#include "../../Systems/LogSystem/Log.h"
#include "../../Systems/Utils/xorstr.h"
#include "../../Systems/Utils/StringCrypt/StringCrypt.h"
#include "../../Systems/Memory/memory.h"
#include "../../Globals/Globals.h"
#include "../../Systems/Utils/utils.h"

#include <mutex>

#pragma comment(lib, "Ws2_32.lib")


#define SALT xorstr_("pjA5w1hoyzKCFEnk19hwtB8K11rCkWU1")
#define communication_key xorstr_("bfdgsam8ujf80942unv08wdnb08adu98") // 32 bytes para AES-256
#define communication_iv xorstr_("nviuofdsanbv890j") // 16 bytes para AES

Communication::Communication( ) {

}

Communication::~Communication( ) {
	stop( );
}

bool Communication::isRunning( ) const {
	if ( this->ThreadObject->IsThreadSuspended( this->ThreadObject->GetHandle( ) ) ) {

		LogSystem::Get( ).Log( xorstr_( "Failed to run thread" ) );
	}

	if ( !this->ThreadObject->IsThreadRunning( this->ThreadObject->GetHandle( ) ) && !this->ThreadObject->IsShutdownSignalled( ) ) {

		LogSystem::Get( ).Log( xorstr_( "Failed to run thread" ) );
	}
}

SOCKET Communication::openConnection( const char * serverIp , int serverPort ) {
	WSADATA wsaData;
	int iResult;

	// Inicializa Winsock
	iResult = WSAStartup( MAKEWORD( 2 , 2 ) , &wsaData );
	if ( iResult != 0 ) {
		LogSystem::Get( ).ConsoleLog( _COMMUNICATION , xorstr_( "wsa startup error: " ) + std::to_string( WSAGetLastError( ) ) , RED );
		return INVALID_SOCKET;
	}

	// Cria o socket do cliente
	SOCKET ConnectSocket = socket( AF_INET , SOCK_STREAM , IPPROTO_TCP );
	if ( ConnectSocket == INVALID_SOCKET ) {
		LogSystem::Get( ).ConsoleLog( _COMMUNICATION , xorstr_( "socket creation error: " ) + std::to_string( WSAGetLastError( ) ) , RED );
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
		LogSystem::Get( ).ConsoleLog( _COMMUNICATION , xorstr_( "attempting connection" ) , GRAY );
		std::this_thread::sleep_for( std::chrono::seconds( 2 ) );
	}

	if ( iResult == SOCKET_ERROR ) {
		LogSystem::Get( ).ConsoleLog( _COMMUNICATION , xorstr_( "connection error: " ) + std::to_string( WSAGetLastError( ) ) , RED );
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
		LogSystem::Get( ).ConsoleLog( _COMMUNICATION , xorstr_( "Invalid socket." ) , RED );
		return false;
	}

	std::string encryptedMessage;

	if ( !Utils::Get( ).encryptMessage( message , encryptedMessage , communication_key , communication_iv ) ) {
		LogSystem::Get( ).ConsoleLog( _COMMUNICATION , xorstr_( "Failed to encrypt the message." ) , RED );
		return false;
	}

	long int messageSize = encryptedMessage.size( );

	std::string messageSizeStr = std::to_string( messageSize );
	int SizeBackup = messageSizeStr.size( );
	//message_size bufer = char * 35 - 1 ( end of the strin \0 )
	messageSizeStr.insert( 0 , 34 - SizeBackup , '0' );  // Insere 'quantidade_zeros' zeros no início
	// 0000001348

	if ( send( ClientSocket , messageSizeStr.c_str( ) , messageSizeStr.size( ) , 0 ) == SOCKET_ERROR ) {
		LogSystem::Get( ).ConsoleLog( _COMMUNICATION , xorstr_( "Failed to send message size." ) , RED );
		return false;
	}

	//pause, so the server can process it
	std::this_thread::sleep_for( std::chrono::milliseconds( 150 ) );

	int totalSent = 0;
	while ( totalSent < messageSize ) {
		int sent = send( ClientSocket , encryptedMessage.c_str( ) + totalSent , messageSize - totalSent , 0 );
		if ( sent == SOCKET_ERROR ) {
			LogSystem::Get( ).ConsoleLog( _COMMUNICATION , xorstr_( "Failed to send encrypted message." ) , RED );
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
		LogSystem::Get( ).ConsoleLog( _COMMUNICATION , xorstr_( "Failed to receive message size." ) , COLORS::RED );
		closesocket( ClientSocket );
		return xorstr_( " " );
	}

	sizeBuffer[ received ] = '\0';
	std::string sizeString( sizeBuffer );




	if ( !isNumeric( sizeString ) ) {
		closesocket( ClientSocket );
		LogSystem::Get( ).ConsoleLog( _COMMUNICATION  , xorstr_( "Received invalid size: " ) + sizeString , COLORS::RED );
		return xorstr_( "" );
	}

	int messageSize;
	try {
		messageSize = std::stoi( sizeString );
	}
	catch ( const std::invalid_argument & ) {
		LogSystem::Get( ).ConsoleLog( _COMMUNICATION  , xorstr_( "Invalid message size" ) , COLORS::RED );
		closesocket( ClientSocket );
		return xorstr_( " " );
	}
	catch ( const std::out_of_range & ) {
		LogSystem::Get( ).ConsoleLog( _COMMUNICATION  , xorstr_( "Message size out of range" ) , COLORS::RED );
		closesocket( ClientSocket );
		return xorstr_( " " );
	}


	const int MAX_MESSAGE_SIZE = 50 * 1024 * 1024; // Limite de 50 MB
	if ( messageSize <= 0 || messageSize > MAX_MESSAGE_SIZE ) {
		LogSystem::Get( ).ConsoleLog( _COMMUNICATION  , xorstr_( "Invalid message size." ) , COLORS::RED );
		closesocket( ClientSocket );
		return xorstr_( " " );
	}

	char * buffer = new( std::nothrow ) char[ messageSize ];
	if ( !buffer ) {
		LogSystem::Get( ).ConsoleLog( _COMMUNICATION  , xorstr_( "Failed to allocate memory for message." ) , COLORS::RED );
		closesocket( ClientSocket );
		return xorstr_( " " );
	}

	bool FailedReceive = false;
	int totalReceived = 0;
	while ( totalReceived < messageSize ) {
		received = recv( ClientSocket , buffer + totalReceived , messageSize - totalReceived , 0 );
		if ( received <= 0 ) {
			LogSystem::Get( ).ConsoleLog( _COMMUNICATION  , xorstr_( "Failed to receive encrypted message." ) , COLORS::RED );
			delete[ ] buffer;
			closesocket( ClientSocket );
			FailedReceive = true;
			break;
		}
		totalReceived += received;
	}

	if ( FailedReceive ) {
		LogSystem::Get( ).ConsoleLog( _COMMUNICATION  , xorstr_( "Failed to receive" ) , COLORS::RED );
		return xorstr_( " " );
	}

	if ( totalReceived < messageSize ) {
		LogSystem::Get( ).ConsoleLog( _COMMUNICATION  , xorstr_( "Received missing message" ) , COLORS::RED );
		delete[ ] buffer;
		closesocket( ClientSocket );
		return xorstr_( " " );
	}

	std::string encryptedMessage( buffer , messageSize );
	delete[ ] buffer;

	if ( encryptedMessage.empty( ) ) {
		LogSystem::Get( ).ConsoleLog( _COMMUNICATION  , xorstr_( "Empty message received." ) , COLORS::RED );
		closesocket( ClientSocket );
		return xorstr_( " " );
	}

	if ( !Utils::Get( ).decryptMessage( encryptedMessage , encryptedMessage , communication_key , communication_iv ) ) {
		LogSystem::Get( ).ConsoleLog( _COMMUNICATION  , xorstr_( "Failed to decrypt the message." ) , COLORS::RED );
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

std::mutex QueueMessagesMutex;

void Communication::AddMessageToQueue( std::string message ) {
	std::lock_guard<std::mutex> lock( QueueMessagesMutex );
	this->QueuedMessages.emplace_back( message );
}


void Communication::threadFunction( ) {
	const char * ipAddress = "127.0.0.10";

	LogSystem::Get( ).ConsoleLog( _COMMUNICATION  , xorstr_( "Sucessfully attached" ) , WHITE );

	int ConnectionTries = 0;
	SOCKET ConnectSocket = openConnection( xorstr_( "127.0.0.10" ) , 8080 );

	if ( ConnectSocket == INVALID_SOCKET ) {
		LogSystem::Get( ).Log( xorstr_( "[701] Can't open connection!\n" ) );
	}

	LogSystem::Get( ).ConsoleLog( _COMMUNICATION , xorstr_( "Sucessfully connected to server" ) , GREEN );

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
	bool m_running = true;

	std::this_thread::sleep_for( std::chrono::seconds( 5 ) );

	while ( m_running ) {
		std::this_thread::sleep_for( std::chrono::seconds( 5 ) );

		//The message expected
		this->ExpectedMessage = Mem::Get( ).GenerateHash( this->ExpectedMessage + SALT );

		// Recebe mensagem do cliente
		std::string Message = receiveMessage( ConnectSocket , 10 );
		if ( !Message.empty( ) ) {
			if ( Message != this->ExpectedMessage ) {
				LogSystem::Get( ).Log( xorstr_( "[client][802] client hash mismatch, expected: \n" ) + this->ExpectedMessage + ", " + Message );
			}
			else {
				LogSystem::Get( ).ConsoleLog( _COMMUNICATION , this->ExpectedMessage , GRAY );
				//update message sent			
				UpdatePingTime( );
			}
		}
		else if ( !PingInTime( ) ) {
			LogSystem::Get( ).Log( xorstr_( "[client][303] Can`t find server answer!" ) );
		}


		{
			std::lock_guard<std::mutex> lock( QueueMessagesMutex );
			if ( QueuedMessages.empty( ) ) {
				this->ExpectedMessage = Mem::Get( ).GenerateHash( this->ExpectedMessage + SALT );
				sendMessage( ConnectSocket , this->ExpectedMessage );
			}
			else {
				sendMessage( ConnectSocket , QueuedMessages.at( 0 ) );
			}
		}

	}

	closeConnection( ConnectSocket );
}