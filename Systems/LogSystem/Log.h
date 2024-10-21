#pragma once
#include <string>
#include "../Utils/singleton.h"

class LogSystem : public CSingleton<LogSystem>
{ 
public:
	void Log( std::string Message, std::string File = "" );
	void LogWithMessageBox( std::string Message , std::string BoxMessage );
};

