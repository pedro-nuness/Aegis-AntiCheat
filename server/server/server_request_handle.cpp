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

bool Server::RequestBanIP( std::string IP , std::string * Buffer ) {
	std::lock_guard<std::mutex> lock( connectionMutex );

	std::unordered_map<std::string , Connection> ConnectionMap = _globals.ConnectionMap;
	bool found = ( ConnectionMap.find( ( IP ) ) != ConnectionMap.end( ) );

	std::unordered_map<std::string , Connection> CachedConnectionSet;
	LoadConnectionSet( CachedConnectionSet , xorstr_( "player_registry.log" ) );

	bool foundincache = ( CachedConnectionSet.find( ( IP ) ) != CachedConnectionSet.end( ) );

	if ( !found && !foundincache )
	{
		*Buffer = xorstr_( "The ip '" ) + IP + xorstr_( "' isn't connected and don't have a server registry!" );
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

bool Server::RequestUnbanIp( std::string IP , std::string * Buffer ) {

	std::unordered_map<std::string , Connection> ConnectionMap;
	{
		ConnectionMap = _globals.BannedPlayers;
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


std::string Server::GetConnectedPlayers( ) {


	std::unordered_map<std::string , Connection> ConnectionMap;
	{
		std::lock_guard<std::mutex> lock( connectionMutex );
		ConnectionMap = _globals.ConnectionMap;
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

	std::string Result = "";

	std::unordered_map<std::string , Connection>  connectionMapCopy;
	{
		connectionMapCopy = _globals.ConnectionMap;
		std::lock_guard<std::mutex> lock( connectionMutex );
	}

	bool found = ( connectionMapCopy.find( ( Ip ) ) != connectionMapCopy.end( ) );
	if ( !found ) {
		Result = xorstr_( "The ip '" ) + Ip + xorstr_( "' isn't connected to the server!\n Screenshot will be sent when the player connects" );
	}
	else {
		Result = xorstr_( "Sent screenshot request to " ) + Ip + xorstr_( "!" );
	}

	{
		std::lock_guard<std::mutex> lock( ScreenshotMutex );
		_globals.RequestedScreenshot.insert( Ip );
	}

	return Result;
}



