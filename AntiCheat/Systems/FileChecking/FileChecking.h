#pragma once
#include "../Utils/singleton.h"
#include <string>

enum F_CHECKER {
	DUMPER,
	CLIENT
};

enum FILECHECK_RETURN {
	FAILED,
	SUCESS,
	SUCESS_NEED_RESTART
};

class FileChecking : public CSingleton<FileChecking>
{

	bool isLauncherValid( );
	bool isGameValid( std::string GameName );
	bool CheckCurrentPath( );
	bool UpdateRegValues( );
	bool CheckHash( );

	bool SearchFiles( );
	bool GetNickname( );
	bool GetSteamID( std::string * Buffer = nullptr );
	FILECHECK_RETURN CheckWindowsDumpSetting( );
public:
	bool CheckFile( F_CHECKER File );
	bool ValidateFiles( );
};

