#include "Log.h"
#include "File/File.h"
#include "../../Utils/utils.h"
#include "../../Utils/xorstr.h"

#include "../../Globals/Globals.h"
#include "../../Utils/StringCrypt/StringCrypt.h"

#include "../../Utils/utils.h"

#include <iostream>
#include "../../externals/json.hpp">

#include <mutex>

using nlohmann::json;

std::mutex PrintMutex;


void LogSystem::ConsoleLog( MODULE_SENDER sender , std::string Message , COLORS _col ) {
	std::lock_guard<std::mutex> lock( PrintMutex );

	std::string custom_text = xorstr_( "undefined" );
	COLORS custom_col = RED;

	switch ( sender ) {
	case _DETECTION:
		custom_text = xorstr_( "detection" );
		custom_col = LIGHT_RED;
		break;
	case _COMMUNICATION:
		custom_text = xorstr_( "communication" );
		custom_col = LIGHT_BLUE;
		break;
	case _TRIGGERS:
		custom_text = xorstr_( "triggers" );
		custom_col = YELLOW;
		break;
	case _MONITOR:
		custom_text = xorstr_( "thread monitor" );
		custom_col = LIGHT_GREEN;
		break;
	case _SERVER:
		custom_text = xorstr_( "server communication" );
		custom_col = DARK_BLUE;
		break;
	case _SERVER_MESSAGE:
		custom_text = xorstr_( "server message" );
		custom_col = LIGHT_YELLOW;
		break;
	case _CHECKER:
		custom_text = xorstr_( "checker" );
		custom_col = PURPLE;
		break;
	case _ANTIDEBUGGER:
		custom_text = xorstr_( "anti-debugger" );
		custom_col = LIGHTER_BLUE;
		break;
	case _HWID:
		custom_text = xorstr_( "hwid" );
		custom_col = LIGHTER_BLUE;
		break;
	case _MAIN:
		custom_text = xorstr_( "main" );
		custom_col = GRAY;
		break;
	case _PUNISH:
		custom_text = xorstr_( "punish" );
		custom_col = RED;
		break;
	case _PREVENTIONS:
		custom_text = xorstr_( "preventions" );
		custom_col = PINK;
		break;
	case _LOG:
		custom_text = xorstr_( "LOG" );
		custom_col = RED;
		break;
	case _LISTENER:
		custom_text = xorstr_( "LISTENER" );
		custom_col = LIGHT_YELLOW;
		break;
	}

#if true

	Warn( custom_col , custom_text );
	ColoredText( xorstr_( " " ) + Message + xorstr_( "\n" ) , _col );

#else



	Warn( custom_col , custom_text );
	ColoredText( xorstr_( " " ) + Message + xorstr_( "\n" ) , _col );
#endif
}

void LogSystem::Warn( COLORS color , std::string custom_text )
{
	std::string text = custom_text == ( "" ) ? ( "-" ) : custom_text;
	ColoredText( xorstr_( "[" ) , WHITE );
	ColoredText( text , color );
	ColoredText( xorstr_( "] " ) , WHITE );
}

void LogSystem::ColoredText( std::string text , COLORS color )
{
	HANDLE hConsole = GetStdHandle( STD_OUTPUT_HANDLE );
	SetConsoleTextAttribute( hConsole , color );
	std::cout << text;
	SetConsoleTextAttribute( hConsole , WHITE );
}

