#include "Log.h"
#include "File/File.h"
#include "../Utils/utils.h"
#include "../Utils/xorstr.h"

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

void LogSystem::LogWithMessageBox( std::string Message , std::string BoxMessage ) {
	MessageBox( NULL , BoxMessage.c_str( ) , xorstr_( "Error" ) , MB_OK | MB_ICONERROR );

	std::string FileName =  xorstr_( "AC.output_" ) + Utils::Get( ).GetRandomWord( 5 ) + xorstr_( ".txt" ) ;
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