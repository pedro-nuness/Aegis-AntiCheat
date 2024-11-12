#pragma once
#include <string>
#include "../Utils/singleton.h"


enum COLORS
{
	DARK_BLUE = 1 ,
	GREEN ,
	BLUE ,
	RED ,
	PURPLE ,
	YELLOW ,
	WHITE ,
	GRAY ,
	LIGHT_BLUE ,
	LIGHT_GREEN ,
	LIGHTER_BLUE ,
	LIGHT_RED ,
	PINK ,
	LIGHT_YELLOW ,
	LIGHT_WHITE
};


enum MODULE_SENDER {
	_TRIGGERS ,
	_DETECTION ,
	_MONITOR ,
	_COMMUNICATION ,
	_SERVER_MESSAGE ,
	_SERVER ,
	_ANTIDEBUGGER ,
	_CHECKER ,
	_HWID ,
	_MAIN ,
	_PUNISH ,
	_PREVENTIONS ,
	_LOG
};




class LogSystem : public CSingleton<LogSystem>
{ 
	void ColoredText( std::string text , COLORS color );
	void Warn( COLORS color , std::string custom_text = "" );

public:
	void SaveCachedLogsToFile( std::string LastLog );

	void Log( std::string Message, std::string File = "" );
	void LogWithMessageBox( std::string Message , std::string BoxMessage );
	void ConsoleLog( MODULE_SENDER Sender , std::string Message , COLORS _col );
};

