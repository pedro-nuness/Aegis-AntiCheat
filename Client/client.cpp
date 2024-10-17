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

#include "../Systems/Utils/utils.h"
#include "../Systems/Monitoring/Monitoring.h"
#include "../Systems/Hardware/hardware.h"
#include "../../Globals/Globals.h"

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#include <nlohmann/json.hpp>

using json = nlohmann::json;

client::client( ) {}
client::~client( ) {}

bool client::InitializeConnection( ) {
	WSADATA wsaData;
	if ( WSAStartup( MAKEWORD( 2 , 2 ) , &wsaData ) != 0 ) {
		Utils::Get( ).WarnMessage( _SERVER , xorstr_( "WSAStartup failed." ) , RED );
		return false;
	}

	SOCKET sock = socket( AF_INET , SOCK_STREAM , 0 );
	if ( sock == INVALID_SOCKET ) {
		Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Socket creation failed." ) , RED );
		WSACleanup( );
		return false;
	}

	sockaddr_in serverAddr;
	const int serverPort = this->Port;

	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons( serverPort );
	serverAddr.sin_addr.s_addr = inet_addr( this->ipaddres.c_str( ) );

	if ( connect( sock , ( sockaddr * ) &serverAddr , sizeof( serverAddr ) ) == SOCKET_ERROR ) {
		Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Connection to server failed. Error code: " ) + std::to_string( WSAGetLastError( ) ) , RED );
		closesocket( sock );
		WSACleanup( );
		return false;
	}

	this->CurrentSocket = sock;
	Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Connected successfully." ) , GREEN );
	return true;
}

bool client::CloseConnection( ) {
	bool Result = true;

	if ( this->CurrentSocket != INVALID_SOCKET ) {
		if ( closesocket( this->CurrentSocket ) == SOCKET_ERROR ) {
			int errorCode = WSAGetLastError( );
			Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Failed to close socket. Error code: " ) + std::to_string( errorCode ) , RED );
			Result = false;
		}
		else {
			Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Socket closed successfully." ) , GREEN );
		}

		if ( WSACleanup( ) == SOCKET_ERROR ) {
			int errorCode = WSAGetLastError( );
			Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Failed to cleanup Winsock. Error code: " ) + std::to_string( errorCode ) , RED );
			Result = false;
		}
		else {
			Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Winsock cleaned up successfully." ) , GREEN );
		}
	}

	return Result;
}

bool client::SendData( std::string data , CommunicationType type , bool encrypt ) {
	if ( this->CurrentSocket == INVALID_SOCKET ) {
		Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Invalid socket." ) , RED );
		return false;
	}

	std::string encryptedMessage;
	if ( encrypt ) {
		if ( !Utils::Get( ).encryptMessage( data , encryptedMessage , key , iv ) ) {
			Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Failed to encrypt the message." ) , RED );
			return false;
		}
	}
	else {
		encryptedMessage = data;
	}

	encryptedMessage = xorstr_( "aegis" ) + std::to_string( static_cast< int >( type ) ) + encryptedMessage;
	long int messageSize = encryptedMessage.size( );

	Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Sending message..." ) , BLUE );
	Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Message size: " ) + std::to_string( messageSize ) , LIGHT_BLUE );

	std::string messageSizeStr = xorstr_( "aegis" ) + std::to_string( messageSize );
	if ( send( this->CurrentSocket , messageSizeStr.c_str( ) , messageSizeStr.size( ) , 0 ) == SOCKET_ERROR ) {
		Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Failed to send message size." ) , RED );
		return false;
	}

	int totalSent = 0;
	while ( totalSent < messageSize ) {
		int sent = send( this->CurrentSocket , encryptedMessage.c_str( ) + totalSent , messageSize - totalSent , 0 );
		if ( sent == SOCKET_ERROR ) {
			Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Failed to send encrypted message." ) , RED );
			closesocket( this->CurrentSocket );
			WSACleanup( );
			return false;
		}
		totalSent += sent;
	}

	Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Message sent successfully." ) , GREEN );
	return true;
}

bool GetHWIDJson( json & js ) {
	std::vector<std::string> MacAddress = hardware::Get( ).getMacAddress( );
	if ( MacAddress.empty( ) ) {
		return false;
	}

	js[ xorstr_( "mac" ) ] = MacAddress;


	std::string DiskID = "";

	if ( !hardware::Get( ).GetDiskSerialNumber( &DiskID ) ) {
		return false;
	}

	if ( DiskID.empty( ) )
		return false;

	js[ xorstr_( "disk" ) ] = DiskID;

	std::string MotherboardID = "";

	if ( !hardware::Get( ).GetMotherboardSerialNumber( &MotherboardID ) )
		return false;

	if ( MotherboardID.empty( ) )
		return false;

	js[ xorstr_( "mb" ) ] = MotherboardID;


	std::vector<int> Ports { 4444, 4040, 8080 };
	std::string Ip;
	for ( auto port : Ports ) {
		Ip = hardware::Get( ).GetIp( 8080 );

		if ( !Ip.empty( ) )
			break;
	}

	if ( Ip.empty( ) ) {
		return false;
	}

	js[ xorstr_( "ip" ) ] = Ip;

	std::string Nickname = Globals::Get( ).Nickname;
	if ( Utils::Get( ).GenerateStringHash( Nickname ) != Globals::Get( ).NicknameHash ) {
		js[ xorstr_( "warn_message" ) ] = xorstr_( "Nickname hash corrupted, user may have changed its user!" );
	}

	js[ xorstr_("nickname") ] = Nickname;

	std::vector<std::string> LoggedUsers;
	
	if ( !hardware::Get( ).GetLoggedUsers( &LoggedUsers ) ) {
		Utils::Get( ).WarnMessage( _SERVER , xorstr_( "failed to get logged users!" ) , RED );
		return false;
	}

	if ( LoggedUsers.empty( ) ) {
		Utils::Get( ).WarnMessage( _SERVER , xorstr_( "logged users empty!" ) , RED );
		return false;
	}

	


	return true;
}

bool client::SendPingToServer( ) {
	json js;
	if ( !GetHWIDJson( js ) ) {
		Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Can't get HWID!" ) , YELLOW );
		return false;
	}

	if ( !InitializeConnection( ) ) {
		Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Failed to initialize connection!" ) , RED );
		return false;
	}

	bool success = SendData( js.dump( ) , CommunicationType::PING );
	CloseConnection( );

	return success;
}

bool client::SendMessageToServer( std::string Message ) {
	if ( Message.empty( ) ) {
		Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Empty message!" ) , YELLOW );
		return false;
	}

	json js;
	if ( !GetHWIDJson( js ) ) {
		Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Can't get HWID JSON!" ) , YELLOW );
		return false;
	}

	js[ xorstr_( "message" ) ] = Message;
	if ( !InitializeConnection( ) ) {
		Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Failed to initialize connection!" ) , RED );
		return false;
	}

	bool success = SendData( js.dump( ) , CommunicationType::MESSAGE );
	CloseConnection( );

	return success;
}

bool client::SendPunishToServer( std::string Message , bool Ban ) {
	if ( Message.empty( ) ) {
		Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Empty message!" ) , YELLOW );
		return false;
	}

	json js;
	if ( !GetHWIDJson( js ) ) {
		Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Can't get HWID JSON!" ) , YELLOW );
		return false;
	}

	HBITMAP screen = Monitoring::Get( ).CaptureScreenBitmap( );
	std::vector<BYTE> bitmapData = Monitoring::Get( ).BitmapToByteArray( screen );
	if ( bitmapData.empty( ) ) {
		Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Can't get screen bitmap!" ) , YELLOW );
		return false;
	}

	std::string hash = Utils::Get( ).GenerateHash( bitmapData );
	if ( hash.empty( ) ) {
		Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Can't generate hash!" ) , YELLOW );
		return false;
	}

	BITMAP bitmap;
	GetObject( screen , sizeof( BITMAP ) , &bitmap );
	js[ xorstr_( "image" ) ] = bitmapData;
	js[ xorstr_( "image_width" ) ] = bitmap.bmWidth;
	js[ xorstr_( "image_height" ) ] = bitmap.bmHeight;
	js[ xorstr_( "image_hash" ) ] = hash;
	js[ xorstr_( "message" ) ] = Message;

	if ( !InitializeConnection( ) ) {
		Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Failed to initialize connection!" ) , RED );
		return false;
	}

	bool success = SendData( js.dump( ) , Ban ? CommunicationType::BAN : CommunicationType::WARN , false );
	if ( !CloseConnection( ) ) {
		Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Failed to close connection!" ) , RED );
		return false;
	}

	return success;
}
