#pragma once
#include <string>
#include <windows.h>
#include <vector>

#include "../utils/singleton.h"

class memory : public CSingleton<memory>
{
public:

	std::string GetFileHash( std::string path );
	std::string GetProcessPath( DWORD processID );
	std::string GenerateHash( std::string msg );
	bool ReadFileToMemory( const std::string & file_path , std::vector<uint8_t> * out_buffer );
	std::string GetProcessExecutablePath( DWORD processID );
};

