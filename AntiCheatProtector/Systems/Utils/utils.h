#pragma once

#include "singleton.h"
#include <string>


class Utils : public CSingleton<Utils>
{
public:

	char * GenerateRandomString( int length ); //make sure to delete[] memory after
	wchar_t * GenerateRandomWString( int length ); //make sure to delete[] memory after




	bool ExistsFile( const std::string & name );
	bool CheckStrings( std::string bString1 , std::string bExpectedResult );
	int RandomNumber( int min , int max );
	bool isNumber( const std::string & str );
	bool encryptMessage( const std::string & plaintext , std::string & ciphertext , const std::string & key , const std::string & iv );
	bool decryptMessage( const std::string & ciphertext , std::string & plaintext , const std::string & key , const std::string & iv );

	std::string GetRandomWord( int size );
	std::string GetRandomLetter( );
	std::string GetRandomCharacter( );
	std::string GenerateRandomKey( int size );
	std::string DownloadString( std::string URL );
};
