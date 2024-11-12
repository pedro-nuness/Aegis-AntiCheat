#pragma once

#include <Windows.h>
#include "singleton.h"
#include <string>
#include <vector>


class Utils : public CSingleton<Utils>
{
public:

	bool ExistsFile( const std::string & name );
	bool CheckStrings( std::string bString1 , std::string bExpectedResult );

	int RandomNumber( int min , int max );
	
	bool isNumber( const std::string & str );
	
	char * GenerateRandomString( int length ); //make sure to delete[] memory after
	wchar_t * GenerateRandomWString( int length ); //make sure to delete[] memory after
	

	bool encryptMessage( const std::string & plaintext , std::string & ciphertext , const std::string & key , const std::string & iv );
	bool decryptMessage( const std::string & ciphertext , std::string & plaintext , const std::string & key , const std::string & iv );
	std::string GenerateHash( const std::vector<BYTE> & input );
	std::string GenerateStringHash( const std::string & input );

	std::string GetRandomWord( int size );
	std::string GetRandomLetter( );
	std::string GetRandomCharacter( );
	std::string GenerateRandomKey( int size );
	std::string DownloadString( std::string URL );


	std::string ConvertLPCWSTRToString( LPCWSTR wideString );
};
