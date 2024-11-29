#include "Log.h"
#include "File/File.h"
#include "../Utils/utils.h"
#include "../Utils/xorstr.h"

#include "../../Modules/ThreadGuard/ThreadGuard.h"
#include "../../Globals/Globals.h"
#include "../Utils/StringCrypt/StringCrypt.h"

#include "../Memory/memory.h"
#include "../Utils/utils.h"

#include <iostream>




std::mutex PrintMutex;


bool Running = false;

void DetachModules( std::string Message , std::string BoxMessage , bool ShowMessageBox ) {


	//Multiple Log calls
	if ( Running )
		return;

	Running = true;

	LogSystem::Get( ).ConsoleLog( _LOG , Message , LIGHT_WHITE );

	if ( Globals::Get( ).GuardMonitorPointer != nullptr ) {
		//Stop threads
		ThreadGuard * Guard = reinterpret_cast< ThreadGuard * >( Globals::Get( ).GuardMonitorPointer );

		std::vector<HANDLE> threadsObject = Guard->GetRunningThreadHandle();

		Guard->ThreadObject->SignalShutdown( true );

		DWORD dwWaitResult = WaitForMultipleObjectsEx(
			static_cast< DWORD >( threadsObject.size( ) ) ,  // Pass the size of the vector
			threadsObject.data( ) ,                      // Pass a pointer to the underlying array
			TRUE ,
			INFINITE ,
			TRUE
		);
	}

	HANDLE hProcess = Mem::Get( ).GetProcessHandle( Globals::Get( ).ProtectProcess );
	if ( hProcess != NULL ) {
		BOOL result = TerminateProcess( hProcess , 0 );
		CloseHandle( hProcess );
	}

	LogSystem::Get( ).ConsoleLog( _LOG , xorstr_( "All threads turnned off!" ) , GREEN );

	LogSystem::Get( ).SaveCachedLogsToFile( Message );

	if ( ShowMessageBox )
		MessageBox( NULL , BoxMessage.c_str( ) , xorstr_( "Error" ) , MB_OK | MB_ICONERROR );


	exit( 0 );
}

std::vector<CryptedString> CachedLogs;

#define log_key xorstr_("fmu843q0fpgonamgfjkang08fgd94qgn")
#define log_iv xorstr_("f43qjg98adnmdamn")

void LogSystem::SaveCachedLogsToFile( std::string LastLog ) {


	std::string FileName = xorstr_( "AC.output_" ) + Utils::Get( ).GetRandomWord( 5 ) + xorstr_( ".txt" );
	File LogFile( "ACLogs\\" , FileName );

	for ( auto & Log : CachedLogs ) {
		std::string * Str = StringCrypt::Get( ).DecryptString( Log );
		std::string EncryptedLog;
		if ( Utils::Get( ).encryptMessage( *Str , EncryptedLog , log_key , log_iv ) )
			LogFile.Write( EncryptedLog );
		StringCrypt::Get( ).CleanString( Str );
	}
	LogFile.Write( LastLog );
}

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

	while ( CachedLogs.size( ) > 50 ) {
		CachedLogs.erase( CachedLogs.begin( ) );
	}
	CachedLogs.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "[" ) + custom_text + xorstr_( "] " ) + Message ) );

	Warn( custom_col , custom_text );
	ColoredText( xorstr_( " " ) + Message + xorstr_( "\n" ) , _col );

#else



	Warn( custom_col , custom_text );
	ColoredText( xorstr_( " " ) + Message + xorstr_( "\n" ) , _col );
#endif
}

void LogSystem::Log( std::string Message , std::string nFile ) {
	std::thread( DetachModules , Message , "" , false ).detach( );
}

void LogSystem::LogWithMessageBox( std::string Message , std::string BoxMessage ) {
	std::thread( DetachModules , Message , BoxMessage , true ).detach( );
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

