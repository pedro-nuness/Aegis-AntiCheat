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


void Server::SaveConnectionSet( std::unordered_map<std::string , Connection> * Set , std::string filename ) {
	json js;

	if ( Set->empty( ) ) {
		std::ofstream file( filename );
		if ( file.is_open( ) ) {
			file.close( );
		}
		return;
	}

	for ( auto it = Set->begin( ); it != Set->end( );) {
		js[ it->first ][ xorstr_( "MAC" ) ] = it->second.GetMac( );
		js[ it->first ][ xorstr_( "DISK" ) ] = it->second.GetDiskID( );
		js[ it->first ][ xorstr_( "BIOS" ) ] = it->second.GetMotherboard( );
		js[ it->first ][ xorstr_( "NICK" ) ] = it->second.GetNickname( );
		js[ it->first ][ xorstr_( "STEAM" ) ] = it->second.GetSteamID( );
		++it;
	}

	// Salva em um arquivo .json
	std::ofstream file( filename );
	if ( file.is_open( ) ) {
		file << std::setw( 4 ) << js;
		file.close( );
	}
	else {
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Failed to open banned_players.json for writing." ) , RED );
	}
}

void Server::LoadConnectionSet( std::unordered_map<std::string , Connection> & Set , std::string filename ) {
	File SetList( filename );

	if ( SetList.Exists( ) ) {
		std::string bannedlistContent = SetList.Read( );
		if ( bannedlistContent.empty( ) ) {
			utils::Get( ).WarnMessage( _SERVER , xorstr_( "Connection list empty!" ) , YELLOW );
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
			}

			// Outros campos

			Connection Con( value[ xorstr_( "NICK" ) ] , value[ xorstr_( "STEAM" ) ] , MAC , value[ xorstr_( "BIOS" ) ] , value[ xorstr_( "DISK" ) ] , key , time( 0 ) );

			Set[ key ] = Con;
		}
	}
	else {
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "No file found while loading connection set. Starting with empty sets." ) , YELLOW );
	}
}

void Server::LoadBlockedSet( ) {

	std::lock_guard<std::mutex> lock( connectionMutex );  // Protege o acesso a ConnectionMap

	File bannedlist( xorstr_( "banned_players.json" ) );

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
				_globals.blockedMacs.emplace( mac );
			}

			// Outros campos
			_globals.blockedBIOS.emplace( value[ xorstr_( "BIOS" ) ] );
			_globals.blockedDisks.emplace( value[ xorstr_( "DISK" ) ] );

			Connection Con( value[ xorstr_( "NICK" ) ] , value[ xorstr_( "STEAM" ) ] , MAC , value[ xorstr_( "BIOS" ) ] , value[ xorstr_( "DISK" ) ] , key , time( 0 ) );

			_globals.BannedPlayers[ key ] = Con;
		}
	}
	else {
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "No banned_players.json file found. Starting with empty sets." ) , YELLOW );
	}
}

void Server::CacheConnections( ) {

	std::unordered_map<std::string , Connection> TempCurrentConnectionMap;

	{
		std::lock_guard<std::mutex> lock( connectionMutex );  // Protege o acesso a ConnectionMap
		TempCurrentConnectionMap = _globals.ConnectionMap;
	}

	if ( TempCurrentConnectionMap.empty( ) ) {
		return;
	}

	std::unordered_map<std::string , Connection> TempAllTimeConnectionMap;

	LoadConnectionSet( TempAllTimeConnectionMap , xorstr_( "player_registry.log" ) );

	if ( TempAllTimeConnectionMap.empty( ) ) {
		SaveConnectionSet( &TempCurrentConnectionMap , xorstr_( "player_registry.log" ) );
		return;
	}

	for ( auto it_current = TempCurrentConnectionMap.begin( ); it_current != TempCurrentConnectionMap.end( ); it_current++ ) {
		if ( TempAllTimeConnectionMap.find( it_current->first ) == TempAllTimeConnectionMap.end( ) ) {
			TempAllTimeConnectionMap[ it_current->first ] = it_current->second;
		}
	}

	SaveConnectionSet( &TempAllTimeConnectionMap , xorstr_( "player_registry.log" ) );

}
