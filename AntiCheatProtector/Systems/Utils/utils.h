#pragma once

#include "singleton.h"
#include <string>

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

class Utils : public CSingleton<Utils>
{
public:
	void ColoredText( std::string text , COLORS color );
	bool ExistsFile( const std::string & name );
	bool CheckStrings( std::string bString1 , std::string bExpectedResult );
	void Warn( COLORS color , std::string custom_text = "" );
	void WarnMessage( COLORS color , std::string custom_text, std::string Message, COLORS _col );
	int RandomNumber( int min , int max );
	bool isNumber( const std::string & str );
	

	std::string GetRandomWord( int size );
	std::string GetRandomLetter( );
	std::string DownloadString( std::string URL );
};
