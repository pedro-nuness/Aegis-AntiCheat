#pragma once
#include "../Utils/singleton.h"
#include <string>

enum F_CHECKER {
	DUMPER,
	CLIENT
};

class FileChecking : public CSingleton<FileChecking>
{

	bool isLauncherValid( );
	bool isGameValid( std::string GameName );
	bool CheckCurrentPath( );
	bool CheckHash( );

	bool SearchFiles( );
	bool GetNickname( );
	bool GetSteamID( std::string * Buffer = nullptr );
	bool CheckWindowsDumpSetting( );
public:
	bool CheckFile( F_CHECKER File );
	bool ValidateFiles( );
};

