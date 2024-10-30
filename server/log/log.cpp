#include "Log.h"
#include "../utils/File/File.h"
#include "../utils/utils.h"
#include "../utils/xorstr.h"

#include "../../Globals/Globals.h"
#include "../Memory/memory.h"

#include <iostream>

void LogSystem::Log( std::string Message , std::string nFile ) {
	std::string FileName = nFile.empty( ) ? xorstr_( "SV.output_" ) + utils::Get( ).GetRandomWord( 5 ) + xorstr_( ".txt" ) : nFile;
	File LogFile( "" , FileName );
	LogFile.Write( Message );

	exit( 0 );
}

void LogSystem::LogWithMessageBox( std::string Message , std::string BoxMessage ) {
	std::wstring wBoxMessage( BoxMessage.begin( ) , BoxMessage.end( ) );
	// Exibir a MessageBox em Unicode
	MessageBoxW( NULL , wBoxMessage.c_str( ) , L"Error" , MB_OK | MB_ICONERROR );

	//std::string FileName = xorstr_( "SV.output_" ) + utils::Get( ).GetRandomWord( 5 ) + xorstr_( ".txt" );
	//File LogFile( "" , FileName );
	//LogFile.Write( Message );


	std::cout << Message << "\n";

	exit( 0 );
}