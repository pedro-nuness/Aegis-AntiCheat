#pragma once
#include "../Utils/singleton.h"
#include <string>

enum F_CHECKER {
	SCANNER,
	WINSOCK
};

class FileChecking : public CSingleton<FileChecking>
{
	bool isFilesValid( );
	bool isLauncherValid( );
	bool isGameValid( std::string GameName );
	bool CheckCurrentPath( );

public:
	bool CheckFile( F_CHECKER File );
	bool ValidateFiles( );
};

