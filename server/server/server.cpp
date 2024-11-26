#include <winsock2.h>

#include "server.h"
#include <iostream>
#include <string>
#include <ws2tcpip.h>
#include <unordered_set>
#include <thread>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <utility>
#include <comdef.h>

#include <dpp/colors.h>

#include "../webhook/webhook.h"
#include "../utils/utils.h"
#include "../image/image.h"
#include "../globals/globals.h"
#include "../memory/memory.h"


#include "../utils/File/File.h"

#include <filesystem>

namespace fs = std::filesystem;

#pragma comment(lib, "ws2_32.lib")

#include <nlohmann/json.hpp>

using json = nlohmann::json;

#include "../config/config.h"


#define server_key xorstr_("ib33o5m8zsqlcgys3w46cfmtn8ztg1kn") // 32 bytes para AES-256
#define server_iv xorstr_("ume9ugz3m7lgch1z") // 16 bytes para AES


enum WHOOKTYPE {
	NOTHING ,
	MESSAGE_ ,
	MESSAGE_FILE ,
	BAN_ ,
	WARN_ ,
};



struct WHookRequest {

	WHOOKTYPE Type = WHOOKTYPE::NOTHING;
	std::string Message = "undefined message";
	std::string Filename = "undefined";
	std::string Ip = "undefined";
	uint32_t Color = 0;

public:

	WHookRequest( WHOOKTYPE type , std::string m , std::string f , std::string ip , uint32_t c ) {
		this->Type = type;
		this->Message = m;
		this->Filename = f;
		this->Color = c;
		this->Ip = ip;
	}

	std::string GetMessage_( ) { return this->Message; }
	std::string GetFilename_( ) { return this->Filename; }
	uint32_t GetColor_( ) { return this->Color; }
	std::string GetIP( ) { return this->Ip; }
	WHOOKTYPE GetType( ) { return this->Type; }

};

std::vector<WHookRequest> WebhookList;

Server::Server( ) {
}

void ProcessWebHookRequests( ) {

	//utils::Get( ).WarnMessage( _SERVER , xorstr_( "Sending webhook requests!" ) , LIGHT_BLUE );  // Informational messages often use blue.

	for ( int i = 0; i < WebhookList.size( ); i++ ) {

		WHookRequest request = WebhookList[ i ];

		switch ( request.GetType( ) ) {
		case WARN_:
			utils::Get( ).WarnMessage( _SERVER , xorstr_( "Sending warning webhook!" ) , YELLOW );  // Warnings are commonly associated with yellow.
			globals::Get( ).whook.SendWebHookPunishMent( request.GetMessage_( ) , request.GetFilename_( ) , request.GetIP( ) , false );
			break;
		case BAN_:
			utils::Get( ).WarnMessage( _SERVER , xorstr_( "Sending ban webhook!" ) , RED );  // Bans typically are marked with red for severity.
			globals::Get( ).whook.SendWebHookPunishMent( request.GetMessage_( ) , request.GetFilename_( ) , request.GetIP( ) , true );
			break;
		case MESSAGE_:
			utils::Get( ).WarnMessage( _SERVER , xorstr_( "Sending message webhook!" ) , LIGHT_GREEN );  // General messages can be green for success or neutral action.
			globals::Get( ).whook.SendWebHookMessage( request.GetMessage_( ) , xorstr_( "AntiCheat Message" ) , request.GetColor_( ) );
			break;
		case MESSAGE_FILE:
			utils::Get( ).WarnMessage( _SERVER , xorstr_( "Sending message with file webhook!" ) , LIGHT_BLUE );  // File-related actions can remain informational with blue.
			globals::Get( ).whook.SendWebHookMessageWithFile( request.GetMessage_( ) , request.GetFilename_( ) , request.GetIP( ) , request.GetColor_( ) );
			break;
		}

		std::this_thread::sleep_for( std::chrono::seconds( 2 ) );
	}

	// utils::Get( ).WarnMessage( _SERVER , xorstr_( "Sent webhook requests!" ) , GREEN );  // Completion messages use green for success.

	WebhookList.clear( );
}

void Server::validateconnections( ) {
	while ( true ) {
		std::this_thread::sleep_for( std::chrono::seconds( 20 ) );
		globals::Get( ).ValidatingConnections = true;
		//	utils::Get( ).WarnMessage( _SERVER , xorstr_( "Validating connections!" ) , LIGHT_BLUE );

		// Validate connection Ping, erase disconnected players
		{
			std::lock_guard<std::mutex> lock( connectionMutex );  // Protege o acesso a ConnectionMap

			for ( auto it = globals::Get( ).ConnectionMap.begin( ); it != globals::Get( ).ConnectionMap.end( );) {
				//utils::Get( ).WarnMessage( _SERVER , xorstr_( "Last ping of " ) + it->first + xorstr_( ": " ) + std::to_string( it->second.GetLastPing( ) ) + xorstr_( " seconds!" ) , WHITE );  // White for general information.

				// If the last ping is too high, remove the connection
				if ( it->second.GetLastPing( ) >= config::Get( ).GetPingTolerance( ) ) {
					utils::Get( ).WarnMessage( _SERVER , xorstr_( "IP " ) + it->first + xorstr_( " disconnected." ) , RED );  // Red for disconnection or error.
					it = globals::Get( ).ConnectionMap.erase( it );
					continue;
				}

				++it;
			}
		}

		SaveBlockedSets( );

		ProcessWebHookRequests( );

		globals::Get( ).ValidatingConnections = false;
	}
}

void Server::SaveBlockedSets( ) {
	json js;

	if ( globals::Get( ).BannedPlayers.empty( ) ) {
		std::ofstream file( xorstr_( "banned_players.json" ) );
		if ( file.is_open( ) ) {
			file.close( );
		}
		return;
	}

	for ( auto it = globals::Get( ).BannedPlayers.begin( ); it != globals::Get( ).BannedPlayers.end( );) {
		js[ it->first ][ xorstr_( "MAC" ) ] = it->second.GetMac( );
		js[ it->first ][ xorstr_( "DISK" ) ] = it->second.GetDiskID( );
		js[ it->first ][ xorstr_( "BIOS" ) ] = it->second.GetMotherboard( );
		js[ it->first ][ xorstr_( "NICK" ) ] = it->second.GetNickname( );
		js[ it->first ][ xorstr_( "STEAM" ) ] = it->second.GetSteamID( );
		++it;
	}

	// Salva em um arquivo .json
	std::ofstream file( xorstr_( "banned_players.json" ) );
	if ( file.is_open( ) ) {
		file << std::setw( 4 ) << js;
		file.close( );
	}
	else {
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Failed to open banned_players.json for writing." ) , RED );
	}
}

void Server::LoadBlockedSets( ) {

	std::lock_guard<std::mutex> lock( connectionMutex );  // Protege o acesso a ConnectionMap

	File bannedlist( xorstr_( "banned_players.json" ) );
	utils::Get( ).WarnMessage( _SERVER , xorstr_( "Loading banned players list!" ) , LIGHT_BLUE );

	if ( bannedlist.Exists( ) ) {
		std::string bannedlistContent = bannedlist.Read( );
		if ( bannedlistContent.empty( ) ) {
			utils::Get( ).WarnMessage( _SERVER , xorstr_( "Banned list empty!" ) , YELLOW );
			return;
		}

		json js;
		try {
			js = json::parse( bannedlistContent );
		}
		catch ( const json::parse_error & e ) {
			std::cout << xorstr_( "Failed to parse JSON: " ) << e.what( ) << std::endl;
			return;
		}

		// Iterando sobre o JSON
		for ( const auto & [key , value] : js.items( ) ) {
			if ( !value.contains( xorstr_( "MAC" ) ) ) continue;
			if ( !value.contains( xorstr_( "DISK" ) ) ) continue;
			if ( !value.contains( xorstr_( "BIOS" ) ) ) continue;
			if ( !value.contains( xorstr_( "STEAM" ) ) ) continue;
			if ( !value.contains( xorstr_( "NICK" ) ) ) continue;

			std::vector<std::string> MAC;

			for ( const auto & mac : value[ xorstr_( "MAC" ) ] ) {
				MAC.emplace_back( mac );
				globals::Get( ).blockedMacs.emplace( mac );
			}

			// Outros campos
			globals::Get( ).blockedBIOS.emplace( value[ xorstr_( "BIOS" ) ] );
			globals::Get( ).blockedDisks.emplace( value[ xorstr_( "DISK" ) ] );

			Connection Con( value[ xorstr_( "NICK" ) ] , value[ xorstr_( "STEAM" ) ] , MAC , value[ xorstr_( "BIOS" ) ] , value[ xorstr_( "DISK" ) ] , key , time( 0 ) );

			globals::Get( ).BannedPlayers[ key ] = Con;
		}
	}
	else {
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "No banned_players.json file found. Starting with empty sets." ) , YELLOW );
	}
}



bool CheckHWID( const json & js ) {

	const std::vector<std::string> requiredFields = {
		xorstr_( "mb" ),
		xorstr_( "disk" ),
		xorstr_( "mac" ),
		xorstr_( "ip" ),
		xorstr_( "nickname" ),
		xorstr_( "steamid" )
	};

	for ( const auto & field : requiredFields ) {
		if ( !js.contains( field ) || js[ field ].empty( ) ) {
			utils::Get( ).WarnMessage( _SERVER , xorstr_( "Can't get " ) + field + xorstr_( "!" ) , RED );
			return false;
		}
	}

	return true;
}

bool Server::IsDiskBanned( const std::string & Disk ) {
	std::lock_guard<std::mutex> lock( connectionMutex );
	return globals::Get( ).blockedDisks.find( ( Disk ) ) != globals::Get( ).blockedDisks.end( );
}

bool Server::IsBiosBanned( const std::string & Bios ) {
	std::lock_guard<std::mutex> lock( connectionMutex );
	return globals::Get( ).blockedBIOS.find( ( Bios ) ) != globals::Get( ).blockedBIOS.end( );
}

bool Server::IsMacBanned( const std::vector<std::string> & Macs ) {
	std::lock_guard<std::mutex> lock( connectionMutex );
	for ( const std::string & Mac : Macs ) {
		if ( globals::Get( ).blockedMacs.find( ( Mac ) ) != globals::Get( ).blockedMacs.end( ) )
			return true;
	}
	return false;
}

bool Server::IsSteamBanned( const std::vector<std::string> & Steams ) {
	std::lock_guard<std::mutex> lock( connectionMutex );
	for ( const std::string & Steam : Steams ) {
		if ( globals::Get( ).blockedSteamID.find( ( Steam ) ) != globals::Get( ).blockedSteamID.end( ) )
			return true;
	}
	return false;
}

bool Server::RequestBanIP( std::string IP , std::string * Buffer ) {
	std::lock_guard<std::mutex> lock( connectionMutex );

	std::unordered_map<std::string , Connection> ConnectionMap = globals::Get( ).ConnectionMap;
	bool found = ( ConnectionMap.find( ( IP ) ) != ConnectionMap.end( ) );
	if ( !found )
	{
		*Buffer = xorstr_( "The ip '" ) + IP + xorstr_( "' isn't connected to the server!" );
		return false;
	}

	if ( BanPlayer( ( IP ) ) ) {
		*Buffer = xorstr_( "The ip '" ) + IP + xorstr_( "' has been banned successfully!" );
		return true;
	}
	else {
		//TODO: Handle disconnected players
	}

	*Buffer = xorstr_( "The ip '" ) + IP + xorstr_( "' couldn't be banned, unexpected error!" );
	return false;
}

bool Server::UnbanIP( std::string IP ) {
	std::lock_guard<std::mutex> lock( connectionMutex );

	utils::Get( ).WarnMessage( _SERVER , xorstr_( "Trying to unban " ) + ( IP ) , GRAY );

	if ( globals::Get( ).BannedPlayers.find( ( IP ) ) != globals::Get( ).BannedPlayers.end( ) ) {
		Connection & BannedPlayer = globals::Get( ).BannedPlayers[ IP ];

		std::string Disk = BannedPlayer.GetDiskID( );
		std::string Bios = BannedPlayer.GetMotherboard( );
		std::vector<std::string> Mac = BannedPlayer.GetMac( );
		std::vector<std::string> SteamID = BannedPlayer.GetSteamID( );

		auto Found = globals::Get( ).blockedDisks.find( ( Disk ) );
		while ( Found != globals::Get( ).blockedDisks.end( ) ) {
			utils::Get( ).WarnMessage( _SERVER , xorstr_( "Erased " ) + ( Disk ) +xorstr_( " from blocked disks!" ) , GRAY );
			globals::Get( ).blockedDisks.erase( Disk );
			Found = globals::Get( ).blockedDisks.find( ( Disk ) );
		}


		Found = globals::Get( ).blockedBIOS.find( ( Bios ) );
		while ( Found != globals::Get( ).blockedBIOS.end( ) ) {
			utils::Get( ).WarnMessage( _SERVER , xorstr_( "Erased " ) + ( Bios ) +xorstr_( " from blocked bios!" ) , GRAY );
			globals::Get( ).blockedBIOS.erase( Bios );

			Found = globals::Get( ).blockedBIOS.find( ( Bios ) );
		}

		for ( auto mAddress : Mac ) {
			Found = globals::Get( ).blockedMacs.find( ( mAddress ) );
			while ( Found != globals::Get( ).blockedMacs.end( ) ) {
				utils::Get( ).WarnMessage( _SERVER , xorstr_( "Erased " ) + ( mAddress ) +xorstr_( " from blocked macs!" ) , GRAY );
				globals::Get( ).blockedMacs.erase( mAddress );

				Found = globals::Get( ).blockedMacs.find( ( mAddress ) );
			}
		}

		for ( auto Steam : SteamID ) {
			Found = globals::Get( ).blockedSteamID.find( ( Steam ) );
			while ( Found != globals::Get( ).blockedSteamID.end( ) ) {
				utils::Get( ).WarnMessage( _SERVER , xorstr_( "Erased " ) + ( Steam ) +xorstr_( " from steam ids!" ) , GRAY );
				globals::Get( ).blockedSteamID.erase( Steam );

				Found = globals::Get( ).blockedSteamID.find( ( Steam ) );
			}
		}

		globals::Get( ).BannedPlayers.erase( IP );
		SaveBlockedSets( );

		return true;
	}
	else {
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Tried to unban a not banned player!" ) , RED );
	}

	return false;
}

bool Server::SendData( std::string data , SOCKET socket ) {
	if ( socket == INVALID_SOCKET ) {
		utils::Get( ).WarnMessage( _SENDER , xorstr_( "Invalid socket." ) , RED );
		return false;
	}

	std::string encryptedMessage;

	if ( !utils::Get( ).encryptMessage( data , encryptedMessage , server_key , server_iv ) ) {
		utils::Get( ).WarnMessage( _SENDER , xorstr_( "Failed to encrypt the message." ) , RED );
		return false;
	}

	if ( send( socket , encryptedMessage.c_str( ) , encryptedMessage.size( ) , 0 ) == SOCKET_ERROR )
		return false;

	return true;
}

bool Server::RequestUnbanIp( std::string IP , std::string * Buffer ) {

	std::unordered_map<std::string , Connection> ConnectionMap;
	{
		ConnectionMap = globals::Get( ).BannedPlayers;
	}
	bool found = ( ConnectionMap.find( ( IP ) ) != ConnectionMap.end( ) );
	if ( !found )
	{
		*Buffer = xorstr_( "The ip '" ) + IP + xorstr_( "' isn't banned!" );
		return false;
	}

	if ( UnbanIP( ( IP ) ) ) {
		*Buffer = xorstr_( "The ip '" ) + IP + xorstr_( "' has been unbanned successfully!" );
		return true;
	}
	else {
		//TODO: Handle disconnected players
	}

	*Buffer = xorstr_( "The ip '" ) + IP + xorstr_( "' couldn't be unbanned, unexpected error!" );
	return false;
}


enum REQUEST_TYPE {
	SCREENSHOT
};

std::string Server::GetConnectedPlayers( ) {


	std::unordered_map<std::string , Connection> ConnectionMap;
	{
		std::lock_guard<std::mutex> lock( connectionMutex );
		ConnectionMap = globals::Get( ).ConnectionMap;
	}

	if ( ConnectionMap.empty( ) ) {
		return xorstr_( "There's no players connected to the server :cry:" );
	}

	std::string Result = xorstr_( "\n" );

	for ( auto it = ConnectionMap.begin( ); it != ConnectionMap.end( ); ) {
		Result += xorstr_( "- **" ) + it->second.GetNickname( ) + xorstr_( "** - `" ) + it->second.GetIp( ) + xorstr_( "`\n" );
		++it;
	}

	return Result;
}

std::string Server::RequestScreenshotFromClient( std::string Ip ) {

	std::lock_guard<std::mutex> lock( connectionMutex );


	auto & connectionMap = globals::Get( ).ConnectionMap;
	bool found = ( connectionMap.find( ( Ip ) ) != connectionMap.end( ) );

	if ( !found ) {
		return xorstr_( "The ip '" ) + Ip + xorstr_( "' isn't connected to the server!" );
	}

	json js;
	js[ xorstr_( "request_type" ) ] = REQUEST_TYPE::SCREENSHOT;
	js[ xorstr_( "message" ) ] = xorstr_( "screenshot request" );

	return xorstr_( "Sent screenshot request to " ) + Ip + xorstr_( "!" );
}

CommunicationResponse Server::receiveping( const std::string & encryptedMessage ) {
	std::string hardware = encryptedMessage;

	json js;
	try {
		js = json::parse( hardware );
	}
	catch ( const json::parse_error & e ) {
		std::cout << xorstr_( "Failed to parse JSON: " ) << e.what( ) << std::endl;
		return RECEIVE_ERROR;
	}

	if ( !CheckHWID( js ) ) {
		return RECEIVE_ERROR;
	}

	std::vector<std::string> Mac = js[ xorstr_( "mac" ) ];
	std::string DiskID = js[ xorstr_( "disk" ) ];
	std::string MotherboardID = js[ xorstr_( "mb" ) ];
	std::string Ip = js[ xorstr_( "ip" ) ];
	std::string Nick = js[ xorstr_( "nickname" ) ];
	std::vector<std::string> Steam = js[ xorstr_( "steamid" ) ];

	if ( IsDiskBanned( DiskID ) || IsBiosBanned( MotherboardID ) || IsMacBanned( Mac ) || IsSteamBanned( Steam ) ) {
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Banned user " ) + ( Ip ) +xorstr_( " tried to connect to server!" ) , RED );
		return RECEIVE_BANNED;
	}

	{
		std::lock_guard<std::mutex> lock( connectionMutex );

		auto & connectionMap = globals::Get( ).ConnectionMap;
		bool found = ( connectionMap.find( ( Ip ) ) != connectionMap.end( ) );

		if ( !found ) {
			Connection NewConnection = Connection(
				Nick ,
				Steam ,
				Mac ,
				MotherboardID ,
				DiskID ,
				Ip ,
				time( 0 )
			);

			globals::Get( ).ConnectionMap[ Ip ] = NewConnection;
			utils::Get( ).WarnMessage( _SERVER , xorstr_( "IP " ) + ( Ip ) +xorstr_( " logged in." ) , GRAY );
		}
		else {
			globals::Get( ).ConnectionMap[ ( Ip ) ].Ping( );
			//utils::Get( ).WarnMessage( _SERVER , xorstr_( "IP " ) + ( Ip ) +xorstr_( " pinged." ) , GRAY );
		}
	}

	return RECEIVED;
}

std::string Server::AppendHWIDToString( const std::string & str , const std::string & Ip ) {


	std::lock_guard<std::mutex> lock( connectionMutex );

	auto & connectionMap = globals::Get( ).ConnectionMap;
	bool found = ( connectionMap.find( ( Ip ) ) != connectionMap.end( ) );

	if ( !found ) {
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Can't find connected machine with IP " ) + ( Ip ) , RED );
		return "";
	}

	Connection Player = globals::Get( ).ConnectionMap[ Ip ];
	json Js;

	Js[ xorstr_( "message" ) ] = str;

	std::string HWID;
	{
		HWID += xorstr_( "**Nickname:** `" ) + Player.GetNickname( ) + xorstr_( "`\n" );
		std::vector<std::string> Steam = Player.GetSteamID( );
		for ( size_t i = 0; i < Steam.size( ); i++ ) {
			HWID += xorstr_( "**SteamID[" ) + std::to_string( i ) + xorstr_( "]:** `" ) + Steam[ i ] + xorstr_( "`\n" );
		}

		HWID += xorstr_( "**IP:** `" ) + Ip + xorstr_( "`\n" );
		HWID += xorstr_( "**Motherboard:** `" ) + Player.GetMotherboard( ) + xorstr_( "`\n" );
		HWID += xorstr_( "**Disk:** `" ) + Player.GetDiskID( ) + xorstr_( "`\n" );
		std::vector<std::string> Mac = Player.GetMac( );
		for ( size_t i = 0; i < Mac.size( ); i++ ) {
			HWID += xorstr_( "**Mac[" ) + std::to_string( i ) + xorstr_( "]:** `" ) + Mac[ i ] + xorstr_( "`\n" );
		}
	}

	Js[ xorstr_( "hwid" ) ] = HWID;

	return Js.dump( );
}

bool Server::BanPlayer( const std::string & Ip ) {
	auto & connectionMap = globals::Get( ).ConnectionMap;
	bool found = ( connectionMap.find( Ip ) != connectionMap.end( ) );

	if ( !found ) {
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Tried to ban IP " ) + Ip + xorstr_( " but player is not logged!" ) , RED );
		return false;
	}

	Connection & Player = globals::Get( ).ConnectionMap[ Ip ];

	globals::Get( ).blockedDisks.insert( ( Player.GetDiskID( ) ) );
	globals::Get( ).blockedBIOS.insert( ( Player.GetMotherboard( ) ) );
	for ( const std::string & mac : Player.GetMac( ) ) {
		globals::Get( ).blockedMacs.insert( ( mac ) );
	}
	for ( const std::string & steam : Player.GetSteamID( ) ) {
		globals::Get( ).blockedSteamID.insert( ( steam ) );
	}

	globals::Get( ).BannedPlayers[ ( Ip ) ] = Player;
	utils::Get( ).WarnMessage( _SERVER , xorstr_( "Player " ) + ( Ip ) +xorstr_( " has been banned." ) , RED );

	globals::Get( ).ConnectionMap.erase( Ip );

	SaveBlockedSets( );

	return true;
}


CommunicationResponse Server::receivepunish( const std::string & encryptedMessage , bool ban ) {
	if ( encryptedMessage.empty( ) ) {
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Empty message!" ) , RED );
		return RECEIVE_ERROR;
	}

	json js;
	try {
		js = json::parse( encryptedMessage );
	}
	catch ( const json::parse_error & e ) {
		std::cout << xorstr_( "Failed to parse JSON: " ) << e.what( ) << std::endl;
		return RECEIVE_ERROR;
	}

	// Verificar HWID
	if ( !CheckHWID( js ) ) {
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Can't get hwid!" ) , RED );
		return RECEIVE_ERROR;
	}

	// Verificar campos obrigatórios
	const std::vector<std::string> requiredFields = {
		xorstr_( "image" ),
		xorstr_( "image_width" ),
		xorstr_( "image_height" ),
		xorstr_( "image_hash" ),
		xorstr_( "message" )
	};

	for ( const auto & field : requiredFields ) {
		if ( !js.contains( field ) || js[ field ].empty( ) ) {
			utils::Get( ).WarnMessage( _SERVER , xorstr_( "Can't get " ) + field + xorstr_( "!" ) , RED );
			return RECEIVE_ERROR;
		}
	}

	// Salvar informações da mensagem
	std::string Ip = js[ xorstr_( "ip" ) ];

	// Obter os bytes da imagem e gerar o hash
	std::string ImageHash = js[ xorstr_( "image_hash" ) ];
	std::vector<BYTE> Image = js[ xorstr_( "image" ) ];
	std::string Hash = utils::Get( ).GenerateHash( Image );

	// Verificar a integridade da imagem
	if ( ImageHash != Hash ) {
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Image corrupted!" ) , RED );
	}

	int height = js[ xorstr_( "image_height" ) ];
	int width = js[ xorstr_( "image_width" ) ];

	//utils::Get( ).WarnMessage( _SERVER , xorstr_( "Reconstructing image!" ) , YELLOW );

	// Recriar a imagem
	HBITMAP reconstructedBitmap = image::Get( ).ByteArrayToBitmap( Image , width , height );
	//utils::Get( ).WarnMessage( _SERVER , xorstr_( "Reconstructed bitmap successfully!" ) , GREEN );

	// Criar nome da pasta
	std::string Nickname = js[ xorstr_( "nickname" ) ];
	std::vector<std::string> SteamIDs = js[ xorstr_( "steamid" ) ];
	std::string FolderName = memory::Get( ).GetProcessPath( ::_getpid( ) ) + "\\" + Nickname + xorstr_( "-" ) + SteamIDs[ 0 ];

	//utils::Get( ).WarnMessage( _SERVER , xorstr_( "Folder name: " ) + FolderName , WHITE );

	// Criar diretório se não existir
	if ( !fs::exists( FolderName.c_str( ) ) ) {
		//utils::Get( ).WarnMessage( _SERVER , xorstr_( "Creating directory " ) + FolderName , YELLOW );
		std::this_thread::sleep_for( std::chrono::seconds( 1 ) );
		fs::create_directory( FolderName.c_str( ) );
	}
	else {
		//utils::Get( ).WarnMessage( _SERVER , xorstr_( "Directory " ) + FolderName + xorstr_( " already exists!" ) , GRAY );
	}

	// Salvar a imagem
	std::string Filename = FolderName + "\\" + utils::Get( ).GetRandomWord( 20 ) + xorstr_( ".jpg" );
	image::Get( ).SaveBitmapToFile( reconstructedBitmap , Filename );
	//utils::Get( ).WarnMessage( _SERVER , xorstr_( "Saved image successfully!" ) , GREEN );

	// Liberar o recurso HBITMAP
	DeleteObject( reconstructedBitmap );
	//utils::Get( ).WarnMessage( _SERVER , xorstr_( "Deleted image object successfully!" ) , GREEN );

	json MessageJson;


	// Adicionar o hwid à mensagem
	std::string Message = AppendHWIDToString( js[ xorstr_( "message" ) ] , Ip );
	//utils::Get( ).WarnMessage( _SERVER , xorstr_( "Appended hwid to message!" ) , GREEN );
	//utils::Get( ).WarnMessage( _SERVER , xorstr_( "Sending message to webhook: \n" ) + Message + xorstr_( "\n\n" ) , WHITE );

	std::lock_guard<std::mutex> lock( connectionMutex );

	// Adicionar à lista de Webhook
	if ( ban ) {
		WebhookList.emplace_back( WHookRequest( WHOOKTYPE::BAN_ , Message , Filename , Ip , 0 ) );
		BanPlayer( Ip );
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Computer banned from server!" ) , RED );
	}
	else {
		WebhookList.emplace_back( WHookRequest( WHOOKTYPE::WARN_ , Message , Filename , Ip , 0 ) );
	}

	utils::Get( ).WarnMessage( _SERVER , xorstr_( "Sent ban to webhook request list!" ) , GREEN );

	return RECEIVED;
}

CommunicationResponse Server::receivemessage( const std::string & encryptedMessage ) {
	if ( encryptedMessage.empty( ) ) {
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Empty message!" ) , RED );
		return RECEIVE_ERROR;
	}

	json js;
	try {
		js = json::parse( encryptedMessage );
	}
	catch ( const json::parse_error & e ) {
		std::cout << xorstr_( "Failed to parse JSON: " ) << e.what( ) << std::endl;
		return RECEIVE_ERROR;
	}

	if ( !CheckHWID( js ) ) {
		return RECEIVE_ERROR;
	}

	if ( !js.contains( xorstr_( "message" ) ) || js[ xorstr_( "message" ) ].empty( ) ) {
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Can't get message!" ) , RED );
		return RECEIVE_ERROR;
	}

	std::string Ip = js[ xorstr_( "ip" ) ];
	std::string Message = AppendHWIDToString( js[ xorstr_( "message" ) ] , Ip );

	std::lock_guard<std::mutex> lock( connectionMutex ); // Protege o acesso a ConnectionMap

	WebhookList.emplace_back( WHookRequest( WHOOKTYPE::MESSAGE_ , Message , "" , Ip , dpp::colors::blue_aquamarine ) );

	return RECEIVED;
}

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

			switch ( message.MessageType ) {
			case PING:
				//utils::Get( ).WarnMessage( _SERVER , xorstr_( "Received ping!" ) , WHITE );
				Response = receiveping( message.Message );
				break;
			case BAN:
				//utils::Get( ).WarnMessage( _SERVER , xorstr_( "Received ban!" ) , WHITE );
				Response = receivepunish( message.Message , true );
				break;
			case WARN:
				//utils::Get( ).WarnMessage( _SERVER , xorstr_( "Received warn!" ) , WHITE );
				Response = receivepunish( message.Message , false );
				break;
			case MESSAGE:
				//utils::Get( ).WarnMessage( _SERVER , xorstr_( "Received message!" ) , WHITE );
				Response = receivemessage( message.Message );
				break;
			default:
				utils::Get( ).WarnMessage( _SERVER , xorstr_( "Invalid message type!" ) , RED );
				break;
			}

			if ( !SendData( std::to_string( Response ) , message.Socket ) ) {
				utils::Get( ).WarnMessage( _SERVER , xorstr_( "Failed to send answer to client" ) , RED );
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

	LoadBlockedSets( ); // Carrega os conjuntos bloqueados ao iniciar o servidor



	sockaddr_in serverAddr;
	const int serverPort = 12345;
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
//
//	std::vector<IN_ADDR> AvailableIP;
//
//	// Iterar pelas interfaces disponíveis e escolher o IP
//	for ( struct addrinfo * ptr = res; ptr != nullptr; ptr = ptr->ai_next ) {
//		sockaddr_in * sockaddr_ipv4 = reinterpret_cast< sockaddr_in * >( ptr->ai_addr );
//		if ( sockaddr_ipv4 ) {
//			AvailableIP.emplace_back( sockaddr_ipv4->sin_addr );
//			continue;
//		}
//	}
//	freeaddrinfo( res );
//
//	if ( AvailableIP.empty( ) ) {
//		utils::Get( ).WarnMessage( _SERVER , xorstr_( "No available IP address found." ) , COLORS::RED );
//		WSACleanup( );
//		return;
//	}
//
//	for ( int i = 0; i < AvailableIP.size( ); i++ ) {
//		char ipStr[ INET_ADDRSTRLEN ];
//		inet_ntop( AF_INET , &AvailableIP[ i ] , ipStr , sizeof( ipStr ) );
//
//		std::cout << "[" << i << "] " << ipStr << std::endl;
//	}
//
//	int Option;
//choose:
//	std::cin >> Option;
//	if ( Option >= 0 && Option < AvailableIP.size( ) ) {
//		serverAddr.sin_addr = AvailableIP[ Option ];
//	}
//	else {
//		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Invalid options!" ) , COLORS::RED );
//		goto choose;
//	}



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
	globals::Get( ).SelfIP = ipStr;
	utils::Get( ).WarnMessage( _SERVER , xorstr_( "Server listening on port " ) + std::to_string( serverPort ) , COLORS::GREEN );

	globals::Get( ).ServerOpen = true;

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
	std::string prefix = "aegis";
	std::string sizeString( sizeBuffer );

	size_t pos = sizeString.find( prefix );
	if ( pos != std::string::npos ) {
		sizeString.erase( pos , prefix.length( ) );
	}

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

	pos = encryptedMessage.find( prefix );
	if ( pos != std::string::npos ) {
		encryptedMessage.erase( pos , prefix.length( ) );
	}

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

	// Descriptografar as mensagens conforme necessário
	if ( messageType != BAN && messageType != WARN ) {
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
