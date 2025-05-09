#include <iostream>
#include <string>
#include <winsock2.h>
#include <iphlpapi.h>

#include "client.h"
#include <intrin.h>
#include <sstream>
#include <fstream>
#include <comdef.h>
#include <Wbemidl.h>
#include <thread>

#include "../utils/utils.h"

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#include <nlohmann/json.hpp>

using json = nlohmann::json;

client::client( ) {
	this->Port = readPort( );
}
client::~client( ) {}

std::string portPath = xorstr_( "Software\\AegisPort" );
#define key xorstr_("W86ztLe5cLYZUDRBK61cVTJONv4IlivA")
#define salt xorstr_("pJWjN6fCSfJmfL92vRnkdHUgzVSSYSks")


int client::readPort( ) {
	HKEY hKey;
	char buffer[ 256 ];
	DWORD bufferSize = sizeof( buffer );
	DWORD tipo = 0;

	if ( RegOpenKeyExA( HKEY_CURRENT_USER , portPath.c_str( ) , 0 , KEY_READ , &hKey ) == ERROR_SUCCESS ) {
		if ( RegQueryValueExA( hKey , "Porta" , nullptr , &tipo , reinterpret_cast< LPBYTE >( buffer ) , &bufferSize ) == ERROR_SUCCESS ) {
			if ( tipo == REG_SZ ) {
				RegCloseKey( hKey );
				return std::stoi( buffer );
			}
		}
		RegCloseKey( hKey );
	}

	return 0;
}

bool client::InitializeConnection( ) {
	WSADATA wsaData;
	if ( WSAStartup( MAKEWORD( 2 , 2 ) , &wsaData ) != 0 ) {
		return false;
	}

	SOCKET sock = socket( AF_INET , SOCK_STREAM , 0 );
	if ( sock == INVALID_SOCKET ) {
		//LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Socket creation failed." ) , RED );
		WSACleanup( );
		return false;
	}

	sockaddr_in serverAddr;
	const int serverPort = this->Port;
	if ( !serverPort ) {
		WSACleanup( );
		return false;
	}

	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons( serverPort );
	serverAddr.sin_addr.s_addr = inet_addr( this->ipaddres.c_str( ) );

	if ( connect( sock , ( sockaddr * ) &serverAddr , sizeof( serverAddr ) ) == SOCKET_ERROR ) {
		//LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Connection to server failed. Error code: " ) + std::to_string( WSAGetLastError( ) ) , RED );
		closesocket( sock );
		WSACleanup( );
		return false;
	}

	this->CurrentSocket = sock;
	//LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Connected successfully." ) , GREEN );
	return true;
}

bool client::CloseConnection( ) {
	bool Result = true;

	if ( this->CurrentSocket != INVALID_SOCKET ) {
		if ( closesocket( this->CurrentSocket ) == SOCKET_ERROR ) {
			int errorCode = WSAGetLastError( );
			//LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Failed to close socket. Error code: " ) + std::to_string( errorCode ) , RED );
			Result = false;
		}

		if ( WSACleanup( ) == SOCKET_ERROR ) {
			int errorCode = WSAGetLastError( );
			//LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Failed to cleanup Winsock. Error code: " ) + std::to_string( errorCode ) , RED );
			Result = false;
		}
	}

	return Result;
}

bool client::GetResponse( CommunicationResponse * response ) {
	if ( this->CurrentSocket == INVALID_SOCKET ) {
		//LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Invalid socket." ) , RED );
		return false;
	}

	char sizeBuffer[ 16 ];
	int received = recv( this->CurrentSocket , sizeBuffer , sizeof( sizeBuffer ) , 0 );
	if ( received <= 0 ) {
		//LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Failed to receive message size." ) , RED );
		return false;
	}

	std::string encryptedMessage( sizeBuffer , sizeof( sizeBuffer ) );

	//if ( !Utils::Get( ).decryptMessage( encryptedMessage , encryptedMessage , key , this->IV ) ) {
	////LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Failed to decrypt message" ) , RED );
	//	return false;
	//}

	int messageInt;
	try {
		messageInt = std::stoi( encryptedMessage );
	}
	catch ( const std::invalid_argument & e ) {
		return false;
	}
	catch ( const std::out_of_range & e ) {
		//LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Message out of range" ) , RED );
		return false;
	}

	if ( response != nullptr )
		*response = ( CommunicationResponse ) messageInt;


	return true;
}

bool client::SendData( std::string data , CommunicationType type , bool encrypt ) {
	if ( this->CurrentSocket == INVALID_SOCKET ) {
		//LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Invalid socket." ) , RED );
		return false;
	}

	std::string encryptedMessage;

	encryptedMessage = data;

	if ( encrypt ) {
		if(!Utils::Get( ).encryptMessage( encryptedMessage , encryptedMessage , key , this->iv )){
			return false;
		}
	}

	
	long int messageSize = encryptedMessage.size( );


	std::string messageSizeStr = std::to_string( messageSize );
	int SizeBackup = messageSizeStr.size( );
	//message_size bufer = char * 35 - 1 ( end of the string \0 )
	messageSizeStr.insert( 0 , 34 - SizeBackup , '0' );  // Insere 'quantidade_zeros' zeros no início
	// 000000..001348
	if ( send( this->CurrentSocket , messageSizeStr.c_str( ) , messageSizeStr.size( ) , 0 ) == SOCKET_ERROR ) {
		//LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Failed to send message size." ) , RED );
		return false;
	}

	//pause, so the server can process it
	std::this_thread::sleep_for( std::chrono::milliseconds( 50 ) );

	int totalSent = 0;
	while ( totalSent < messageSize ) {
		int sent = send( this->CurrentSocket , encryptedMessage.c_str( ) + totalSent , messageSize - totalSent , 0 );
		if ( sent == SOCKET_ERROR ) {
			//LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Failed to send encrypted message." ) , RED );
			closesocket( this->CurrentSocket );
			WSACleanup( );
			return false;
		}
		totalSent += sent;
	}

	//LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Message sent successfully." ) , GREEN );
	return true;
}





bool client::SendMessageToServer( std::string Message, CommunicationType type ) {
	if ( Message.empty( ) ) {
		//LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Empty message!" ) , YELLOW );
		return false;
	}

	json js;

	std::string _key = Utils::Get( ).GenerateRandomKey( 256 );

	js[ xorstr_( "message" ) ] = Message;
	js[ xorstr_( "type" ) ] = type;
	js[ xorstr_( "key" ) ] = _key;
	js[ xorstr_( "password" ) ] = Utils::Get( ).GenerateHash( _key + salt );
	if ( !InitializeConnection( ) ) {
		//LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Failed to initialize connection!" ) , RED );
		return false;
	}

	bool success = SendData( js.dump( ) , CommunicationType::MESSAGE );


	CloseConnection( );

	return success;
}

