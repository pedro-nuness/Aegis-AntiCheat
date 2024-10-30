
#include <winsock2.h>

#include "sender.h"

// Inclui bibliotecas padrão C++ e do Windows para networking e outros recursos
#include <iostream>
#include <string>
#include <iphlpapi.h>
#include <intrin.h>
#include <sstream>
#include <fstream>
#include <comdef.h>
#include <Wbemidl.h>
#include <thread>

// Inclui cabeçalhos globais do projeto
#include "../../Globals/Globals.h"
#include "../utils/utils.h"

// Pragma para bibliotecas de linkagem
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")


#define key xorstr_("ib33o5m8zsqlcgys3w46cfmtn8ztg1kn")
#define iv xorstr_("ume9ugz3m7lgch1z")

bool sender::InitializeConnection( ) {

	WSADATA wsaData;
	if ( WSAStartup( MAKEWORD( 2 , 2 ) , &wsaData ) != 0 ) {
		utils::Get( ).WarnMessage( _SENDER , xorstr_( "WSAStartup failed." ) , RED );
		return false;
	}

	SOCKET sock = socket( AF_INET , SOCK_STREAM , 0 );
	if ( sock == INVALID_SOCKET ) {
		utils::Get( ).WarnMessage( _SENDER , xorstr_( "Socket creation failed." ) , RED );
		WSACleanup( );
		return false;
	}

	sockaddr_in serverAddr;
	const int serverPort = this->port;

	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons( serverPort );
	serverAddr.sin_addr.s_addr = inet_addr( this->IpAddress.c_str( ) );

	if ( connect( sock , ( sockaddr * ) &serverAddr , sizeof( serverAddr ) ) == SOCKET_ERROR ) {
		int errorCode = WSAGetLastError( );
		utils::Get( ).WarnMessage( _SENDER , xorstr_( "Connection to server failed. Error code: " ) + std::to_string( errorCode ) , RED );
		closesocket( sock );
		WSACleanup( );
		return false;
	}

	this->CurrentSocket = sock;
	utils::Get( ).WarnMessage( _SENDER , xorstr_( "Connected successfully." ) , GREEN );
	return true;

}

bool sender::CloseConnection( ) {
	bool Result = true;

	if ( this->CurrentSocket == INVALID_SOCKET ) {
		return false;
	}

	if ( closesocket( this->CurrentSocket ) == SOCKET_ERROR ) {
		int errorCode = WSAGetLastError( );
		utils::Get( ).WarnMessage( _SENDER , xorstr_( "Failed to close socket. Error code: " ) + std::to_string( errorCode ) , RED );
		Result = false;
	}

	if ( WSACleanup( ) == SOCKET_ERROR ) {
		int errorCode = WSAGetLastError( );
		utils::Get( ).WarnMessage( _SENDER , xorstr_( "Failed to cleanup Winsock. Error code: " ) + std::to_string( errorCode ) , RED );
		Result = false;
	}

	return Result;
}

bool sender::SendData( std::string data ) {
	if ( this->CurrentSocket == INVALID_SOCKET ) {
		utils::Get( ).WarnMessage( _SENDER , xorstr_( "Invalid socket." ) , RED );
		return false;
	}

	std::string encryptedMessage;

	if ( !utils::Get( ).encryptMessage( data , encryptedMessage , key , iv ) ) {
		utils::Get( ).WarnMessage( _SENDER , xorstr_( "Failed to encrypt the message." ) , RED );
		return false;
	}

	long int messageSize = encryptedMessage.size( );

	utils::Get( ).WarnMessage( _SENDER , xorstr_( "Sending message..." ) , BLUE );
	utils::Get( ).WarnMessage( _SENDER , xorstr_( "Message size: " ) + std::to_string( messageSize ) , LIGHT_BLUE );

	std::string messageSizeStr = std::to_string( messageSize );
	if ( send( this->CurrentSocket , messageSizeStr.c_str( ) , messageSizeStr.size( ) , 0 ) == SOCKET_ERROR ) {
		utils::Get( ).WarnMessage( _SENDER , xorstr_( "Failed to send message size." ) , RED );
		return false;
	}

	// Pause para que o servidor possa processar
	std::this_thread::sleep_for( std::chrono::milliseconds( 50 ) );

	int totalSent = 0;
	while ( totalSent < messageSize ) {
		int sent = send( this->CurrentSocket , encryptedMessage.c_str( ) + totalSent , messageSize - totalSent , 0 );
		if ( sent == SOCKET_ERROR ) {
			utils::Get( ).WarnMessage( _SENDER , xorstr_( "Failed to send encrypted message." ) , RED );
			closesocket( this->CurrentSocket );
			WSACleanup( );
			return false;
		}
		totalSent += sent;
	}

	utils::Get( ).WarnMessage( _SENDER , xorstr_( "Message sent successfully." ) , GREEN );
	return true;

}

bool sender::SendMessageToServer( std::string Message ) {
	if ( !InitializeConnection( ) ) {
		utils::Get( ).WarnMessage( _SENDER , xorstr_( "Failed to initialize connection!" ) , RED );
		return false;
	}

	bool success = SendData( Message );
	if ( !CloseConnection( ) ) {
		utils::Get( ).WarnMessage( _SENDER , xorstr_( "Failed to close connection!" ) , RED );
		return false;
	}

	return success;
}
