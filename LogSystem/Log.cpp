#include "Log.h"
#include "File/File.h"
#include "../Utils/utils.h"

void LogSystem::Log( std::string Message, std::string nFile ) {

	std::string FileName = nFile.empty( ) ? "AC.output_" + Utils::Get( ).GetRandomWord( 5 ) + ".txt" : nFile;
	File LogFile( "" , FileName );
	LogFile.Write( Message );
}