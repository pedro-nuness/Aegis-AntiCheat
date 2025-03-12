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







Server::Server( ) {
}




bool Server::IsDiskBanned( const std::string & Disk ) {
	std::lock_guard<std::mutex> lock( connectionMutex );
	return _globals.blockedDisks.find( ( Disk ) ) != _globals.blockedDisks.end( );
}

bool Server::IsBiosBanned( const std::string & Bios ) {
	std::lock_guard<std::mutex> lock( connectionMutex );
	return _globals.blockedBIOS.find( ( Bios ) ) != _globals.blockedBIOS.end( );
}

bool Server::IsMacBanned( const std::vector<std::string> & Macs ) {
	std::lock_guard<std::mutex> lock( connectionMutex );
	for ( const std::string & Mac : Macs ) {
		if ( _globals.blockedMacs.find( ( Mac ) ) != _globals.blockedMacs.end( ) )
			return true;
	}
	return false;
}

bool Server::IsSteamBanned( const std::vector<std::string> & Steams ) {
	std::lock_guard<std::mutex> lock( connectionMutex );
	for ( const std::string & Steam : Steams ) {
		if ( _globals.blockedSteamID.find( ( Steam ) ) != _globals.blockedSteamID.end( ) )
			return true;
	}
	return false;
}


void Server::ProcessWebHookRequests( ) {

	//utils::Get( ).WarnMessage( _SERVER , xorstr_( "Sending webhook requests!" ) , LIGHT_BLUE );  // Informational messages often use blue.

	for ( int i = 0; i < WebhookList.size( ); i++ ) {

		WHookRequest request = WebhookList[ i ];

		switch ( request.GetType( ) ) {
		case WARN_:
			utils::Get( ).WarnMessage( _SERVER , xorstr_( "Sending warning webhook!" ) , YELLOW );  // Warnings are commonly associated with yellow.
			_globals.whook.SendWebHookPunishMent( request.GetMessage_( ) , request.GetFilename_( ) , request.GetIP( ) , false );
			break;
		case BAN_:
			utils::Get( ).WarnMessage( _SERVER , xorstr_( "Sending ban webhook!" ) , RED );  // Bans typically are marked with red for severity.
			_globals.whook.SendWebHookPunishMent( request.GetMessage_( ) , request.GetFilename_( ) , request.GetIP( ) , true );
			break;
		case MESSAGE_:
			utils::Get( ).WarnMessage( _SERVER , xorstr_( "Sending message webhook!" ) , LIGHT_GREEN );  // General messages can be green for success or neutral action.
			_globals.whook.SendWebHookMessage( request.GetMessage_( ) , xorstr_( "AntiCheat Message" ) , request.GetColor_( ) );
			break;
		case MESSAGE_FILE:
			utils::Get( ).WarnMessage( _SERVER , xorstr_( "Sending message with file webhook!" ) , LIGHT_BLUE );  // File-related actions can remain informational with blue.
			_globals.whook.SendWebHookMessageWithFile( request.GetMessage_( ) , request.GetFilename_( ) , request.GetIP( ) , request.GetColor_( ) );
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
		_globals.ValidatingConnections = true;
		//	utils::Get( ).WarnMessage( _SERVER , xorstr_( "Validating connections!" ) , LIGHT_BLUE );

		std::unordered_set<std::string>  WhitelistedIps = _config.GetWhiteListedPlayers( );

		// Validate connection Ping, erase disconnected players
		{
			std::lock_guard<std::mutex> lock( connectionMutex );  // Protege o acesso a ConnectionMap

			for ( auto it = _globals.ConnectionMap.begin( ); it != _globals.ConnectionMap.end( );) {
				//utils::Get( ).WarnMessage( _SERVER , xorstr_( "Last ping of " ) + it->first + xorstr_( ": " ) + std::to_string( it->second.GetLastPing( ) ) + xorstr_( " seconds!" ) , WHITE );  // White for general information.

				// If the last ping is too high, remove the connection
				if ( it->second.GetLastPing( ) >= _config.GetPingTolerance( ) && !it->second.WhiteListed ) {
					utils::Get( ).WarnMessage( _SERVER , xorstr_( "IP " ) + it->first + xorstr_( " disconnected." ) , RED );  // Red for disconnection or error.
					it = _globals.ConnectionMap.erase( it );
					continue;
				}

				bool FoundInWhitelist = ( WhitelistedIps.find( ( it->first ) ) != WhitelistedIps.end( ) );

				if ( it->second.WhiteListed && !FoundInWhitelist ) {
					utils::Get( ).WarnMessage( _SERVER , xorstr_( "Removed " ) + it->first + xorstr_( " from connection [ WHITELIST ]" ) , GREEN );
					it = _globals.ConnectionMap.erase( it );
					continue;
				}
				++it;
			}


			bool FoundWhiteListedConnection = false;
			for ( std::string WhiteListedIp : WhitelistedIps )
			{
				bool FoundInConnectionMap = ( _globals.ConnectionMap.find( ( WhiteListedIp ) ) != _globals.ConnectionMap.end( ) );

				if ( !FoundInConnectionMap ) {
					Connection NewConnection = Connection(
						utils::Get( ).GenerateRandomKey( 32 ) ,
						{ utils::Get( ).GenerateRandomKey( 32 ) } ,
						{ utils::Get( ).GenerateRandomKey( 32 ) } ,
						utils::Get( ).GenerateRandomKey( 32 ) ,
						utils::Get( ).GenerateRandomKey( 32 ) ,
						WhiteListedIp ,
						time( 0 )
					);
					utils::Get( ).WarnMessage( _SERVER , xorstr_( "Added " ) + WhiteListedIp + xorstr_( " to connection [ WHITELIST ]" ) , GREEN );

					NewConnection.WhiteListed = true;
					_globals.ConnectionMap[ WhiteListedIp ] = NewConnection;
				}
			}
		}

		SaveConnectionSet( &_globals.BannedPlayers , xorstr_( "banned_players.json" ) );

		ProcessWebHookRequests( );

		CacheConnections( );

		_globals.ValidatingConnections = false;
	}
}

std::string Server::AppendHWIDToString( const std::string & str , const std::string & Ip ) {


	std::lock_guard<std::mutex> lock( connectionMutex );

	auto & connectionMap = _globals.ConnectionMap;
	bool found = ( connectionMap.find( ( Ip ) ) != connectionMap.end( ) );

	if ( !found ) {
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Can't find connected machine with IP " ) + ( Ip ) , RED );
		return "";
	}

	Connection Player = _globals.ConnectionMap[ Ip ];
	json Js;

	Js[ xorstr_( "message" ) ] = str;

	std::string HWID;
	{
		HWID += xorstr_( "**Nickname:** `" ) + Player.GetNickname( ) + xorstr_( "`\n" );
		std::vector<std::string> Steam = Player.GetSteamID( );
		for ( size_t i = 0; i < Steam.size( ); i++ ) {
			HWID += xorstr_( "**SteamID[" ) + std::to_string( i ) + xorstr_( "]:** `" ) + Steam[ i ] + xorstr_( "`\n" );
		}

		HWID += xorstr_( "**IP:** `" ) + Ip + xorstr_( " `\n" );
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
	bool Cached = false;

	std::unordered_map<std::string , Connection> & connectionMap = _globals.ConnectionMap;
	bool found = ( connectionMap.find( Ip ) != connectionMap.end( ) );

	if ( !found ) {
		connectionMap.clear( );
		LoadConnectionSet( connectionMap , xorstr_( "player_registry.log" ) );

		if ( connectionMap.empty( ) || ( connectionMap.find( Ip ) == connectionMap.end( ) ) ) {
			utils::Get( ).WarnMessage( _SERVER , xorstr_( "Tried to ban IP " ) + Ip + xorstr_( " but player has no server registry!" ) , RED );
			return false;
		}
		Cached = true;
	}

	Connection & Player = connectionMap[ Ip ];

	_globals.blockedDisks.insert( ( Player.GetDiskID( ) ) );
	_globals.blockedBIOS.insert( ( Player.GetMotherboard( ) ) );

	for ( const std::string & mac : Player.GetMac( ) ) {
		_globals.blockedMacs.insert( ( mac ) );
	}
	for ( const std::string & steam : Player.GetSteamID( ) ) {
		_globals.blockedSteamID.insert( ( steam ) );
	}

	_globals.BannedPlayers[ ( Ip ) ] = Player;
	utils::Get( ).WarnMessage( _SERVER , xorstr_( "Player " ) + ( Ip ) +xorstr_( " has been banned." ) , RED );

	if ( !Cached )
		_globals.ConnectionMap.erase( Ip );

	SaveConnectionSet( &_globals.BannedPlayers , xorstr_( "banned_players.json" ) );

	return true;
}

bool Server::UnbanIP( std::string IP ) {
	std::lock_guard<std::mutex> lock( connectionMutex );

	utils::Get( ).WarnMessage( _SERVER , xorstr_( "Trying to unban " ) + ( IP ) , GRAY );

	if ( _globals.BannedPlayers.find( ( IP ) ) != _globals.BannedPlayers.end( ) ) {
		Connection & BannedPlayer = _globals.BannedPlayers[ IP ];

		std::string Disk = BannedPlayer.GetDiskID( );
		std::string Bios = BannedPlayer.GetMotherboard( );
		std::vector<std::string> Mac = BannedPlayer.GetMac( );
		std::vector<std::string> SteamID = BannedPlayer.GetSteamID( );

		auto Found = _globals.blockedDisks.find( ( Disk ) );
		while ( Found != _globals.blockedDisks.end( ) ) {
			utils::Get( ).WarnMessage( _SERVER , xorstr_( "Erased " ) + ( Disk ) +xorstr_( " from blocked disks!" ) , GRAY );
			_globals.blockedDisks.erase( Disk );
			Found = _globals.blockedDisks.find( ( Disk ) );
		}


		Found = _globals.blockedBIOS.find( ( Bios ) );
		while ( Found != _globals.blockedBIOS.end( ) ) {
			utils::Get( ).WarnMessage( _SERVER , xorstr_( "Erased " ) + ( Bios ) +xorstr_( " from blocked bios!" ) , GRAY );
			_globals.blockedBIOS.erase( Bios );

			Found = _globals.blockedBIOS.find( ( Bios ) );
		}

		for ( auto mAddress : Mac ) {
			Found = _globals.blockedMacs.find( ( mAddress ) );
			while ( Found != _globals.blockedMacs.end( ) ) {
				utils::Get( ).WarnMessage( _SERVER , xorstr_( "Erased " ) + ( mAddress ) +xorstr_( " from blocked macs!" ) , GRAY );
				_globals.blockedMacs.erase( mAddress );

				Found = _globals.blockedMacs.find( ( mAddress ) );
			}
		}

		for ( auto Steam : SteamID ) {
			Found = _globals.blockedSteamID.find( ( Steam ) );
			while ( Found != _globals.blockedSteamID.end( ) ) {
				utils::Get( ).WarnMessage( _SERVER , xorstr_( "Erased " ) + ( Steam ) +xorstr_( " from steam ids!" ) , GRAY );
				_globals.blockedSteamID.erase( Steam );

				Found = _globals.blockedSteamID.find( ( Steam ) );
			}
		}

		_globals.BannedPlayers.erase( IP );
		SaveConnectionSet( &_globals.BannedPlayers , xorstr_( "banned_players.json" ) );

		return true;
	}
	else {
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Tried to unban a not banned player!" ) , RED );
	}

	return false;
}