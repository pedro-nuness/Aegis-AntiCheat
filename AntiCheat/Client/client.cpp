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

#include "../Systems/Utils/utils.h"
#include "../Systems/Monitoring/Monitoring.h"
#include "../Systems/Hardware/hardware.h"
#include "../Systems/Punishing/PunishSystem.h"
#include "../Systems/LogSystem/Log.h"
#include "../../Globals/Globals.h"

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#include <nlohmann/json.hpp>

using json = nlohmann::json;

client::client( ) {}
client::~client( ) {}


#define key xorstr_("ib33o5m8zsqlcgys3w46cfmtn8ztg1kn")
#define iv xorstr_("ume9ugz3m7lgch1z")

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

		if ( WSACleanup( ) == SOCKET_ERROR ) {
			int errorCode = WSAGetLastError( );
			Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Failed to cleanup Winsock. Error code: " ) + std::to_string( errorCode ) , RED );
			Result = false;
		}
	}

	return Result;
}

bool client::GetResponse( CommunicationResponse * response ) {
	if ( this->CurrentSocket == INVALID_SOCKET ) {
		Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Invalid socket." ) , RED );
		return false;
	}

	char sizeBuffer[ 16 ];
	int received = recv( this->CurrentSocket , sizeBuffer , sizeof( sizeBuffer ), 0 );
	if ( received <= 0 ) {
		Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Failed to receive message size." ) , RED );
		return false;
	}

	std::string encryptedMessage( sizeBuffer , sizeof( sizeBuffer ));

	if ( !Utils::Get( ).decryptMessage( encryptedMessage , encryptedMessage , key , iv ) ) {
		Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Failed to decrypt message" ) , RED );
		return false;
	}

	int messageInt;
	try {
		messageInt = std::stoi( encryptedMessage );
	}
	catch ( const std::invalid_argument & e ) {
		return false;
	}
	catch ( const std::out_of_range & e ) {
		Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Message out of range" ) , RED );
		return false;
	}

	if ( response != nullptr )
		*response = ( CommunicationResponse ) messageInt;


	return true;
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


	std::string messageSizeStr = xorstr_( "aegis" ) + std::to_string( messageSize );
	int SizeBackup = messageSizeStr.size( );
	//message_size bufer = char * 35 - 1 ( end of the strin \0 )
	//skip 5, prefix
	messageSizeStr.insert( 5 , 34 - SizeBackup , '0' );  // Insere 'quantidade_zeros' zeros no início
	// aegis0000001348
	if ( send( this->CurrentSocket , messageSizeStr.c_str( ) , messageSizeStr.size( ) , 0 ) == SOCKET_ERROR ) {
		Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Failed to send message size." ) , RED );
		return false;
	}

	//pause, so the server can process it
	std::this_thread::sleep_for( std::chrono::milliseconds( 50 ) );

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
	js[ xorstr_( "nickname" ) ] = Nickname;

	std::vector<std::string> LoggedUsers;
	if ( !hardware::Get( ).GetLoggedUsers( &LoggedUsers ) ) {
		Utils::Get( ).WarnMessage( _SERVER , xorstr_( "failed to get logged users!" ) , RED );
		return false;
	}
	if ( LoggedUsers.empty( ) ) {
		Utils::Get( ).WarnMessage( _SERVER , xorstr_( "logged users empty!" ) , RED );
		return false;
	}

	js[ xorstr_( "steamid" ) ] = LoggedUsers;

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
	CommunicationResponse Response;
	GetResponse( &Response );

	switch ( Response ) {
	case RECEIVED:
		break;
	case RECEIVE_ERROR:
		Utils::Get( ).WarnMessage( _SERVER , xorstr_( "Ping failed!" ) , RED );
		break;
	case RECEIVE_BANNED:
		Utils::Get( ).WarnMessage( _SERVER , xorstr_( "You have been banned!" ) , RED );
		LogSystem::Get( ).LogWithMessageBox( xorstr_("Server denied ping" ) , xorstr_( "You have been banned!" ) );
		break;
	}

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

	if ( !Ban )
		PunishSystem::Get( ).UnsafeSession( );

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
