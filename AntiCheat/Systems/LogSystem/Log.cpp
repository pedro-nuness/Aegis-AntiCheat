#include "Log.h"
#include "File/File.h"
#include "../Utils/utils.h"
#include "../Utils/xorstr.h"

#include "../../Modules/ThreadGuard/ThreadGuard.h"
#include "../../Globals/Globals.h"
#include "../Memory/memory.h"

#include <iostream>

void LogSystem::Log( std::string Message , std::string nFile ) {

	std::string FileName = nFile.empty( ) ? xorstr_("AC.output_") + Utils::Get( ).GetRandomWord( 5 ) + xorstr_(".txt") : nFile;
	File LogFile( "" , FileName );
	LogFile.Write( Message );

	std::cout << Message << "\n";

	HANDLE hProcess = Mem::Get( ).GetProcessHandle( Globals::Get( ).ProtectProcess );
	if ( hProcess != NULL ) {
		BOOL result = TerminateProcess( hProcess , 0 );
		CloseHandle( hProcess );
	}

	exit( 0 );
}

void DetachModules( std::string Message , std::string BoxMessage ) {
	if ( Globals::Get( ).GuardMonitorPointer != nullptr ) {
		//Stop threads
		reinterpret_cast< ThreadGuard * >( Globals::Get( ).GuardMonitorPointer )->ThreadObject->SignalShutdown( true );
		WaitForSingleObject( reinterpret_cast< ThreadGuard * >( Globals::Get( ).GuardMonitorPointer )->ThreadObject->GetHandle( ) , 5000 );
	}

	MessageBox( NULL , BoxMessage.c_str( ) , xorstr_( "Error" ) , MB_OK | MB_ICONERROR );

	std::string FileName = xorstr_( "AC.output_" ) + Utils::Get( ).GetRandomWord( 5 ) + xorstr_( ".txt" );
	File LogFile( "" , FileName );
	LogFile.Write( Message );

	std::cout << Message << "\n";

	HANDLE hProcess = Mem::Get( ).GetProcessHandle( Globals::Get( ).ProtectProcess );
	if ( hProcess != NULL ) {
		BOOL result = TerminateProcess( hProcess , 0 );
		CloseHandle( hProcess );
	}

	exit( 0 );
}


void LogSystem::LogWithMessageBox( std::string Message , std::string BoxMessage ) {
	
	std::thread( DetachModules, Message , BoxMessage).detach( );
}