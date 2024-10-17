#pragma once

#include <Windows.h>
#include "singleton.h"
#include <string>
#include <vector>

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


enum MODULE_SENDER{ 
	_TRIGGERS,
	_DETECTION,
	_MONITOR,
	_COMMUNICATION,
	_SERVER,
	_CHECKER,
	_HWID
};

class Utils : public CSingleton<Utils>
{
public:
	void ColoredText( std::string text , COLORS color );
	bool ExistsFile( const std::string & name );
	bool CheckStrings( std::string bString1 , std::string bExpectedResult );
	void Warn( COLORS color , std::string custom_text = "" );
	int RandomNumber( int min , int max );
	void WarnMessage( MODULE_SENDER Sender , std::string Message , COLORS _col );
	void WarnMessage( COLORS color , std::string custom_text , std::string Message , COLORS _col );
	bool isNumber( const std::string & str );
	
	bool encryptMessage( const std::string & plaintext , std::string & ciphertext , const std::string & key , const std::string & iv );
	std::string GenerateHash( const std::vector<BYTE> & input );
	std::string GenerateStringHash( const std::string & input );

	std::string GetRandomWord( int size );
	std::string GetRandomLetter( );
	std::string GetRandomCharacter( );
	std::string GenerateRandomKey( int size );
	std::string DownloadString( std::string URL );
};
