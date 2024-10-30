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
	void Init( );
	std::vector<char> GeneratePlain( std::string cStr );
	void SaveEncryptedStringsToFile( std::string  filename , CryptedString Str );
public:
	StringCrypt( ) { Init( ); }

	std::string EncryptString( std::string STR);
	std::string * DecryptString( std::string hash);
	std::string * DecryptString( CryptedString string );
	bool CleanString( std::string * sPtr );
	CryptedString GetCryptString( std::string Hash );
};

