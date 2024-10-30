#pragma once
#include <string>
#include "../utils/singleton.h"

class LogSystem : public CSingleton<LogSystem>
{
public:
	void Log( std::string Message , std::string File = "" );
	void LogWithMessageBox( std::string Message , std::string BoxMessage );
};

