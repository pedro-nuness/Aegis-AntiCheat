#include "Log.h"
#include "File/File.h"
#include "../Utils/utils.h"

#include "../../Globals/Globals.h"
#include "../Memory/memory.h"

void LogSystem::Log( std::string Message , std::string nFile ) {

	std::string FileName = nFile.empty( ) ? "AC.output_" + Utils::Get( ).GetRandomWord( 5 ) + ".txt" : nFile;
	File LogFile( "" , FileName );
	LogFile.Write( Message );


	HANDLE hProcess = Mem::Get( ).GetProcessHandle( Globals::Get( ).ProtectProcess );
	if ( hProcess != NULL ) {
		BOOL result = TerminateProcess( hProcess , 0 );
		CloseHandle( hProcess );
	}

	exit( 0 );
}