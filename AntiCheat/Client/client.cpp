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
#include "../Systems/LogSystem/File/File.h"
#include "../Systems/Memory/memory.h"
#include "../../Globals/Globals.h"

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#include <nlohmann/json.hpp>
#include <mutex>

using json = nlohmann::json;


client _client;

client::client( ) {}
client::~client( ) {}


#define key xorstr_("ib33o5m8zsqlcgys3w46cfmtn8ztg1kn")
#define salt xorstr_("8d88db7a1cc2512169bc970c2e2e7498")
#define IV xorstr_("ume9ugz3m7lgch1z")
#define default_encrypt_salt xorstr_("FMJ892FJfni8HNGFJADO432190GFSAMG")

std::mutex ServerSendMutex;

std::string calculateStringSize( const std::string & str ) {
	// Tamanho da string em bytes
	size_t sizeInBytes = str.size( );

	// Converte para KB, MB e GB
	double sizeInKB = static_cast< double >( sizeInBytes ) / 1024;
	double sizeInMB = sizeInKB / 1024;
	double sizeInGB = sizeInMB / 1024;

	// Cria o stream para formatar o retorno
	std::ostringstream result;
	result << std::fixed << std::setprecision( 2 ); // Define precisão para 2 casas decimais

	// Determina a unidade mais apropriada e retorna como string
	if ( sizeInGB >= 1.0 ) {
		result << sizeInGB << " GB";
	}
	else if ( sizeInMB >= 1.0 ) {
		result << sizeInMB << " MB";
	}
	else if ( sizeInKB >= 1.0 ) {
		result << sizeInKB << " KB";
	}
	else {
		result << sizeInBytes << " Bytes";
	}

	return result.str( );
}


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
	//LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Connected successfully." ) , GREEN );
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


bool isNumeric( const std::string & str );

bool client::ReceiveInformation( std::string * buff ) {
	char sizeBuffer[ 35 ];
	int received = recv( this->CurrentSocket , sizeBuffer , sizeof( sizeBuffer ) - 1 , 0 );
	if ( received <= 0 ) {
		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Failed to receive message size." ) , COLORS::RED );
		closesocket( this->CurrentSocket );
		return false;
	}
	sizeBuffer[ received ] = '\0';
	std::string sizeString( sizeBuffer );


	if ( !isNumeric( sizeString ) ) {
		closesocket( this->CurrentSocket );
		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Received invalid size: " ) + sizeString , COLORS::RED );
		return false;
	}

	int messageSize;
	try {
		messageSize = std::stoi( sizeString );
	}
	catch ( const std::invalid_argument & ) {
		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Invalid message size" ) , COLORS::RED );
		closesocket( this->CurrentSocket );
		return false;
	}
	catch ( const std::out_of_range & ) {
		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Message size out of range" ) , COLORS::RED );
		closesocket( this->CurrentSocket );
		return false;
	}

	const int MAX_MESSAGE_SIZE = 50 * 1024 * 1024; // Limite de 50 MB
	if ( messageSize <= 0 || messageSize > MAX_MESSAGE_SIZE ) {
		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Invalid message size." ) , COLORS::RED );
		closesocket( this->CurrentSocket );
		return false;
	}

	char * buffer = new( std::nothrow ) char[ messageSize ];
	if ( !buffer ) {
		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Failed to allocate memory for message." ) , COLORS::RED );
		closesocket( this->CurrentSocket );
		return false;
	}

	bool FailedReceive = false;
	int totalReceived = 0;
	while ( totalReceived < messageSize ) {
		received = recv( this->CurrentSocket , buffer + totalReceived , messageSize - totalReceived , 0 );
		if ( received <= 0 ) {
			LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Failed to receive encrypted message." ) , COLORS::RED );
			delete[ ] buffer;
			closesocket( this->CurrentSocket );
			FailedReceive = true;
			return false;
		}
		totalReceived += received;
	}

	if ( FailedReceive ) {
		return false;
	}

	if ( totalReceived < messageSize ) {
		delete[ ] buffer;
		closesocket( this->CurrentSocket );
		return false;
	}

	std::string encryptedMessage( buffer , messageSize );
	delete[ ] buffer;

	if ( encryptedMessage.empty( ) ) {
		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Empty message received." ) , COLORS::RED );
		closesocket( this->CurrentSocket );
		return false;
	}

	if ( !Utils::Get( ).decryptMessage( encryptedMessage , encryptedMessage , key , IV ) )
	{
		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Failed to decrypt message" ) , COLORS::RED );
		closesocket( this->CurrentSocket );
		return false;
	}


	LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Received " ) + calculateStringSize( encryptedMessage ) + xorstr_( " from server!" ) , COLORS::GRAY );


	if ( buff != nullptr ) {
		*buff = encryptedMessage;
	}

	return true;
}





bool client::GetResponse( Response * res_buff ) {
	if ( res_buff == nullptr )
		return false;


	if ( this->CurrentSocket == INVALID_SOCKET ) {
		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Invalid socket." ) , RED );
		return false;
	}

	std::string ResponseStr;
	if ( !ReceiveInformation( &ResponseStr ) ) {
		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Failed to receive information" ) , RED );
		return false;
	}

	json js;
	try {
		js = json::parse( ResponseStr );
	}
	catch ( json::parse_error error ) {
		LogSystem::Get( ).ConsoleLog( _COMMUNICATION , xorstr_( "failed to parse message to json!" ) , YELLOW );
		return false;
	}

	if ( !js.contains( xorstr_( "response" ) ) || js[ xorstr_( "response" ) ].empty( ) ) {
		return false;
	}

	CommunicationResponse SvResponse = ( CommunicationResponse ) ( js[ xorstr_( "response" ) ] );
	std::string SessionID = xorstr_( "" );
	if ( js.contains( xorstr_( "sessionid" ) ) ) {
		SessionID = js[ xorstr_( "sessionid" ) ];
		if ( SessionID.empty( ) ) {
			LogSystem::Get( ).ConsoleLog( _SERVER_MESSAGE , xorstr_( "Received session id but it's empty!" ) , YELLOW );
		}
	}

	*res_buff = Response( SvResponse , SessionID );

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

	//LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Message sent successfully." ) , GREEN );
	return true;
}





bool client::SendDataToServer( std::string str , CommunicationType type , Response * res_ptr ) {
	if ( res_ptr == nullptr ) {
		return SuccessStatus::NOTHING;
	}


	std::lock_guard<std::mutex> lock( ServerSendMutex );

	/*json js;
	try {
		js = json::parse( str );
	}
	catch ( json::parse_error error ) {
		LogSystem::Get( ).ConsoleLog( _COMMUNICATION , xorstr_( "failed to parse message to json!" ) , YELLOW );
		return false;
	}*/

	SuccessStatus success = NOTHING;

	for ( int i = 0; i < 3; i++ ) {

		if ( !InitializeConnection( ) ) {
			LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Failed to initialize connection!" ) , RED );
			return false;
		}

		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Sending " ) + calculateStringSize( str ) + xorstr_( " to server!" ) , COLORS::GRAY );

		bool Encrypt = true;
		switch ( type ) {
		case WARN:
		case BAN:
		case SCREENSHOT:
			Encrypt = false;
			break;
		}

		if ( SendData( str , type , Encrypt ) )
			success = SUCCESS;
		else
			success = TRYAGAIN;

		Response ServerResponse( NORESPONSE , xorstr_( "" ) );

		if ( success == SUCCESS ) {
			if ( !GetResponse( &ServerResponse ) ) {
				success = TRYAGAIN;
			}
			if ( ServerResponse.GetServerResponse( ) == RECEIVE_ERROR ) {
				success = TRYAGAIN;
			}
		}

		CloseConnection( );
		if ( success == SUCCESS ) {
			*res_ptr = ServerResponse;
			return true;
		}
	}

	return false;
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


	std::string Ip;

	if ( !hardware::Get( ).GetIp( &Ip ) ) {
		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "failed to get ip" ) , RED );
		return false;
	}

	if ( Ip.empty( ) ) {
		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "ip is empty" ) , RED );
		return false;
	}

	js[ xorstr_( "ip" ) ] = Ip;

	std::string Nickname = _globals.Nickname;
	if ( strcmp( Utils::Get( ).GenerateStringHash( Nickname ).c_str( ) , _globals.NicknameHash.c_str( ) ) ) {
		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "nickname hash invalid!" ) , RED );
		return false;
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

	std::string UniqueID;
	if ( !hardware::Get( ).GetUniqueUID( &UniqueID ) ) {
		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "failed to get unique id!" ) , RED );
		return false;
	}

	js[ xorstr_( "uniqueid" ) ] = UniqueID;

	std::string VersionID;
	if ( !hardware::Get( ).GetVersionUID( &VersionID ) ) {
		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "failed to get version id!" ) , RED );
		return false;
	}

	js[ xorstr_( "versionid" ) ] = VersionID;

	return true;
}

bool client::SendPingToServer( ) {

	json js;
	if ( !_globals.LoggedIn ) {
		if ( !GetHWIDJson( js ) ) {
			LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Can't get HWID!" ) , YELLOW );
			return false;
		}
	}
	else {
		std::string Ip;

		if ( !hardware::Get( ).GetIp( &Ip ) ) {
			LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "failed to get ip" ) , RED );
			return false;
		}

		if ( Ip.empty( ) ) {
			LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "ip is empty" ) , RED );
			return false;
		}

		js[ xorstr_( "ip" ) ] = Ip;

		if ( GetIV( ).empty( ) ) {

			if ( GetSessionID( ).empty( ) ) {
				LogSystem::Get( ).Error( xorstr_( "[03] Session ID is empty" ) );
				return false;
			}

			SetIV( Mem::Get( ).GenerateHash( GetSessionID( ) + default_encrypt_salt ) );
		}
		else {
			SetIV( Mem::Get( ).GenerateHash( GetIV( ) + default_encrypt_salt ) );
		}

		js[ xorstr_( "authentication" ) ] = GetIV( );

		LogSystem::Get( ).ConsoleLog( _SERVER_MESSAGE , xorstr_( "Authentication: " ) + GetIV( ) , GREEN );

	}

	Response ServerResponse( NORESPONSE , xorstr_( "" ) );

	if ( !SendDataToServer( js.dump( ) , CommunicationType::PING , &ServerResponse ) )
		return false;
	else {
		switch ( ServerResponse.GetServerResponse( ) ) {
		case RECEIVE_LOGGEDIN:
			_globals.LoggedIn = true;
			LogSystem::Get( ).ConsoleLog( _SERVER_MESSAGE , xorstr_( "Logged In!" ) , GREEN );
			if ( ServerResponse.GetSessionID( ).empty( ) ) {
				LogSystem::Get( ).ConsoleLog( _SERVER_MESSAGE , xorstr_( "LoggedIn, but didn't received session id from server!" ) , RED );
			}
			else {
				SetSessionID( ServerResponse.GetSessionID( ) );
				LogSystem::Get( ).ConsoleLog( _SERVER_MESSAGE , xorstr_( "SessionID: " ) + ServerResponse.GetSessionID( ) , GREEN );
			}
			break;
		case RECEIVE_BANNED:
			LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "You have been banned!" ) , RED );
			LogSystem::Get( ).MessageBoxError( xorstr_( "Server denied ping" ) , xorstr_( "You have been banned!" ) );
			return false;
			break;

		case RECEIVE_NOT_LOGGEDIN:
			LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Disconnected from server" ) , YELLOW );
			_globals.LoggedIn = false;
			SetIV( xorstr_( "" ) );
			SetSessionID( xorstr_( "" ) );
			break;

		case RECEIVED_SCREENSHOTREQUEST:
			_globals.RequestedScreenshot = true;
			break;

		case RECEIVE_ERROR:
			LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Ping failed!" ) , RED );
			return false;
			break;

		case RECEIVED_WRONGAUTH:
			LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Wrong authentication code!" ) , RED );
			return false;
			break;

		case RECEIVE_INVALIDSESSION:
			LogSystem::Get( ).MessageBoxError( xorstr_( "Unverified Session" ) , xorstr_( "Can't verify session integrity" ) );
			return false;
			break;

		}

		return true;
	}


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

	Response ServerResponse( NORESPONSE , xorstr_( "" ) );

	if ( !SendDataToServer( js.dump( ) , CommunicationType::MESSAGE , &ServerResponse ) )
		return false;
	else {
		switch ( ServerResponse.GetServerResponse( ) ) {
		case RECEIVE_ERROR:
			LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Ping failed!" ) , RED );
			return false;
			break;
		}
		return true;
	}
}

bool client::SendPunishToServer( std::string Message , CommunicationType Type ) {

	switch ( Type ) {
	case BAN:
		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Sending BAN punisment to server!" ) , RED );
		break;

	case WARN:
		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Sending WARN punisment to server!" ) , YELLOW );
		break;
	case SCREENSHOT:
		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Sending SCREENSHOT to server!" ) , LIGHT_BLUE );
		break;

	default:
		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Invalid PUNISH To Server Call?" ) , RED );
		return false;
	}


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

	auto bitmapData = Monitoring::Get( ).BitmapToByteArray( screen );

	if ( bitmapData.empty( ) ) {
		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Can't get screen bitmap!" ) , YELLOW );
		return false;
	}

	std::string hash = Utils::Get( ).GenerateHash( bitmapData );
	if ( hash.empty( ) ) {
		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Can't generate hash!" ) , YELLOW );
		return false;
	}

	std::vector<int> CompressedBitmapData = Monitoring::Get( ).CompressToIntermediate( bitmapData );

	if ( CompressedBitmapData.empty( ) ) {
		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Failed to compress bitmap" ) , YELLOW );
		return false;
	}

	js[ xorstr_( "message" ) ] = Message;

	std::string Info = js.dump( );

	if ( !Utils::Get( ).encryptMessage( Info , Info , key , IV ) ) {
		LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Failed to encrypt the message." ) , RED );
		return false;
	}

	js.clear( );
	Info += xorstr_( "endinfo" );

	BITMAP bitmap;
	GetObject( screen , sizeof( BITMAP ) , &bitmap );
	js[ xorstr_( "image" ) ] = CompressedBitmapData;
	js[ xorstr_( "image_width" ) ] = bitmap.bmWidth;
	js[ xorstr_( "image_height" ) ] = bitmap.bmHeight;
	js[ xorstr_( "image_hash" ) ] = hash;

	Info += js.dump( );


	Response ServerResponse( NORESPONSE , xorstr_( "" ) );

	if ( !SendDataToServer( Info , Type , &ServerResponse ) )
		return false;
	else {
		switch ( ServerResponse.GetServerResponse( ) ) {
		case RECEIVE_ERROR:
			LogSystem::Get( ).ConsoleLog( _SERVER , xorstr_( "Punish failed!" ) , RED );
			return false;
			break;
		}
		return true;
	}
}
