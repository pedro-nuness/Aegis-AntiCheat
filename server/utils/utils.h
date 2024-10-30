#pragma once
#include "singleton.h"
#include <string>
#include <windows.h>
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

enum MODULE_SENDER {
	_SENDER ,
	_SERVER ,
	_HWID,
	WEBHOOK
};


class utils : public CSingleton<utils>
{
public:

	void ColoredText( std::string text , COLORS color );
	void Warn( COLORS color , std::string custom_text = "" );
	void WarnMessage( MODULE_SENDER Sender , std::string Message , COLORS _col );
	// void WarnMessage( COLORS color , std::string custom_text , std::string Message , COLORS _col );

	std::string GenerateHash( const std::vector<BYTE> & input );
	bool encryptMessage( const std::string & plaintext , std::string & ciphertext , const std::string & key , const std::string & iv );
	bool decryptMessage( const std::string & ciphertext , std::string & plaintext , const std::string & key , const std::string & iv );
	std::string GetRandomWord( int size );
	std::string GetRandomLetter( );
	std::string GetRandomCharacter( );
	std::string GenerateRandomKey( int size );
	bool CheckStrings( std::string bString1 , std::string bExpectedResult );
};

