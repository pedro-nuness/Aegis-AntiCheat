#pragma once
#include <unordered_map>
#include <string>

#include "../singleton.h"

struct CryptedChar {
	int _Key;
	char Letter;
};

struct CryptedString{
	std::string Hash;
	std::vector<CryptedChar> EncryptedString;
};

class StringCrypt : public CSingleton<StringCrypt>
{
	std::vector<CryptedString> Strings;
	
public:
	StringCrypt( ) { Init( ); }

	void Init( );
	std::string EncryptString( std::string STR);
	std::string * DecryptString( std::string hash);
	std::string * DecryptString( CryptedString string );
	bool CleanString( std::string * sPtr );
	CryptedString GetCryptString( std::string Hash );
	void SaveEncryptedStringsToFile( std::string  filename );
};

