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
#define salt xorstr_("8d88db7a1cc2512169bc970c2e2e7498")
#define IV xorstr_("ume9ugz3m7lgch1z")

bool client::InitializeConnection( ) {
	WSADATA wsaData;
	if ( WSAStartup( MAKEWORD( 2 , 2 ) , &wsaData ) != 0 ) {
		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "WSAStartup failed." ) , RED );
		return false;
	}

	SOCKET sock = socket( AF_INET , SOCK_STREAM , 0 );
	if ( sock == INVALID_SOCKET ) {
		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Socket creation failed." ) , RED );
		WSACleanup( );
		return false;
	}

	sockaddr_in serverAddr;
	const int serverPort = this->Port;

	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons( serverPort );
	serverAddr.sin_addr.s_addr = inet_addr( this->ipaddres.c_str( ) );

	if ( connect( sock , ( sockaddr * ) &serverAddr , sizeof( serverAddr ) ) == SOCKET_ERROR ) {
		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Connection to server failed. Error code: " ) + std::to_string( WSAGetLastError( ) ) , RED );
		closesocket( sock );
		WSACleanup( );
		return false;
	}

	this->CurrentSocket = sock;
	LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Connected successfully." ) , GREEN );
	return true;
}

bool client::CloseConnection( ) {
	bool Result = true;

	if ( this->CurrentSocket != INVALID_SOCKET ) {
		if ( closesocket( this->CurrentSocket ) == SOCKET_ERROR ) {
			int errorCode = WSAGetLastError( );
			LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Failed to close socket. Error code: " ) + std::to_string( errorCode ) , RED );
			Result = false;
		}

		if ( WSACleanup( ) == SOCKET_ERROR ) {
			int errorCode = WSAGetLastError( );
			LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Failed to cleanup Winsock. Error code: " ) + std::to_string( errorCode ) , RED );
			Result = false;
		}
	}

	return Result;
}

bool client::GetResponse( CommunicationResponse * response ) {
	if ( this->CurrentSocket == INVALID_SOCKET ) {
		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Invalid socket." ) , RED );
		return false;
	}

	char sizeBuffer[ 16 ];
	int received = recv( this->CurrentSocket , sizeBuffer , sizeof( sizeBuffer ) , 0 );
	if ( received <= 0 ) {
		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Failed to receive message size." ) , RED );
		return false;
	}

	std::string encryptedMessage( sizeBuffer , sizeof( sizeBuffer ) );

	if ( !Utils::Get( ).decryptMessage( encryptedMessage , encryptedMessage , key , IV ) ) {
		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Failed to decrypt message" ) , RED );
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
		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Message out of range" ) , RED );
		return false;
	}

	if ( response != nullptr )
		*response = ( CommunicationResponse ) messageInt;


	return true;
}

bool client::SendData( std::string data , CommunicationType type , bool encrypt ) {
	if ( this->CurrentSocket == INVALID_SOCKET ) {
		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Invalid socket." ) , RED );
		return false;
	}

	std::string encryptedMessage;
	if ( encrypt ) {
		if ( !Utils::Get( ).encryptMessage( data , encryptedMessage , key , IV ) ) {
			LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Failed to encrypt the message." ) , RED );
			return false;
		}
	}
	else {
		encryptedMessage = data;
	}

	encryptedMessage = std::to_string( static_cast< int >( type ) ) + encryptedMessage;
	long int messageSize = encryptedMessage.size( );


	std::string messageSizeStr = std::to_string( messageSize );
	int SizeBackup = messageSizeStr.size( );
	//message_size bufer = char * 35 - 1 ( end of the string \0 )
	messageSizeStr.insert( 0 , 34 - SizeBackup , '0' );  // Insere 'quantidade_zeros' zeros no início
	// 000000..001348
	if ( send( this->CurrentSocket , messageSizeStr.c_str( ) , messageSizeStr.size( ) , 0 ) == SOCKET_ERROR ) {
		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Failed to send message size." ) , RED );
		return false;
	}

	//pause, so the server can process it
	std::this_thread::sleep_for( std::chrono::milliseconds( 50 ) );

	int totalSent = 0;
	while ( totalSent < messageSize ) {
		int sent = send( this->CurrentSocket , encryptedMessage.c_str( ) + totalSent , messageSize - totalSent , 0 );
		if ( sent == SOCKET_ERROR ) {
			LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Failed to send encrypted message." ) , RED );
			closesocket( this->CurrentSocket );
			WSACleanup( );
			return false;
		}
		totalSent += sent;
	}

	LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Message sent successfully." ) , GREEN );
	return true;
}

bool client::SendDataToServer( std::string str , CommunicationType type ) {
	json js;
	try {
		js = json::parse( str );
	}
	catch ( json::parse_error error ) {
		LogSystem::Get( ).ConsoleLog( _COMMUNICATION , xorstr_( "failed to parse message to json!" ) , YELLOW );
		return false;
	}

	bool success = false;

	if ( !InitializeConnection( ) ) {
		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Failed to initialize connection!" ) , RED );
		return false;
	}

	success = SendData( str , type , type == WARN || type == BAN ? false : true );

	if ( success ) {
		CommunicationResponse response;
		GetResponse( &response );

		switch ( response ) {
		case RECEIVED:
			break;
		case RECEIVE_ERROR:
			LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Ping failed!" ) , RED );
			success = false;
			break;
		case RECEIVE_BANNED:
			LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "You have been banned!" ) , RED );
			LogSystem::Get( ).LogWithMessageBox( xorstr_( "Server denied ping" ) , xorstr_( "You have been banned!" ) );
			success = false;
			break;
		}
	}

	CloseConnection( );


	return success;
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


	std::string Ip = hardware::Get( ).GetIp( );

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
		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "failed to get logged users!" ) , RED );
		return false;
	}
	if ( LoggedUsers.empty( ) ) {
		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "logged users empty!" ) , RED );
		return false;
	}

	js[ xorstr_( "steamid" ) ] = LoggedUsers;

	return true;
}

bool client::SendPingToServer( ) {
	json js;
	if ( !GetHWIDJson( js ) ) {
		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Can't get HWID!" ) , YELLOW );
		return false;
	}

	return SendDataToServer( js.dump( ) , CommunicationType::PING );
}

bool client::SendMessageToServer( std::string Message ) {
	if ( Message.empty( ) ) {
		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Empty message!" ) , YELLOW );
		return false;
	}

	json js;
	if ( !GetHWIDJson( js ) ) {
		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Can't get HWID JSON!" ) , YELLOW );
		return false;
	}

	js[ xorstr_( "message" ) ] = Message;
	return SendDataToServer( js.dump( ) , CommunicationType::MESSAGE );
}

bool client::SendPunishToServer( std::string Message , bool Ban ) {
	if ( !Ban )
		PunishSystem::Get( ).UnsafeSession( );

	if ( Message.empty( ) ) {
		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Empty message!" ) , YELLOW );
		return false;
	}

	json js;
	if ( !GetHWIDJson( js ) ) {
		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Can't get HWID JSON!" ) , YELLOW );
		return false;
	}

	HBITMAP screen = Monitoring::Get( ).CaptureScreenBitmap( );
	std::vector<BYTE> bitmapData = Monitoring::Get( ).BitmapToByteArray( screen );
	if ( bitmapData.empty( ) ) {
		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Can't get screen bitmap!" ) , YELLOW );
		return false;
	}

	std::string hash = Utils::Get( ).GenerateHash( bitmapData );
	if ( hash.empty( ) ) {
		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Can't generate hash!" ) , YELLOW );
		return false;
	}

	BITMAP bitmap;
	GetObject( screen , sizeof( BITMAP ) , &bitmap );
	js[ xorstr_( "image" ) ] = bitmapData;
	js[ xorstr_( "image_width" ) ] = bitmap.bmWidth;
	js[ xorstr_( "image_height" ) ] = bitmap.bmHeight;
	js[ xorstr_( "image_hash" ) ] = hash;
	js[ xorstr_( "message" ) ] = Message;

	return SendDataToServer( js.dump( ) , Ban ? CommunicationType::BAN : CommunicationType::WARN );
}
