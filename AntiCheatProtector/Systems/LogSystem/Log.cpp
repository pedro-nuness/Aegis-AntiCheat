#include "Log.h"
#include "../Utils/File/File.h"
#include "../Utils/utils.h"
#include "../Utils/xorstr.h"

void LogSystem::Log( std::string Message , std::string nFile ) {

	std::string FileName = nFile.empty( ) ? xorstr_("AC_sv.output_") + Utils::Get( ).GetRandomWord( 5 ) + xorstr_(".txt") : nFile;
	File LogFile( "" , FileName );
	LogFile.Write( Message );
	exit( 0 );
}