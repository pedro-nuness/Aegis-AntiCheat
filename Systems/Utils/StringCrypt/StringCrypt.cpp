#include <fstream>
#include "StringCrypt.h"
#include "../utils.h"
#include "../xorstr.h"
#include "../../Memory/memory.h"
#include "../SHA1/sha1.h"
#include "../AES/AES.h"



void StringCrypt::Init( ) {
	CryptedString cStr;

	cStr.Hash = xorstr_("a477c5772e93d5a7f3f91d766d249e0a63b8bef5");
	cStr.EncryptedString = {
		{3052, -127}, {1013, -125}, {1215, -102}, {2441, -66}, {4338, 80},
		{651, -42}, {4603, 102}, {3263, 108}, {4012, -78}, {3516, -90},
		{3405, 45}, {207, -119}, {2524, 77}, {3842, 78}, {1918, -40},
		{3027, 87}
	};

	Strings.emplace_back( cStr );
}

std::vector<char> StringCrypt::GeneratePlain( std::string str ) {
	std::vector<char> Plain;

	for ( auto c : str ) {
		Plain.emplace_back( c );
	}
	return Plain;
}


std::string StringCrypt::EncryptString( std::string str ) {

	std::string Hash = Mem::Get( ).GenerateHash( str );
	CryptedString cStr;
	cStr.Hash = Hash;

	std::string Result;
	for ( int i = 0; i < str.size( ); i++ ) {
		int Num = Utils::Get( ).RandomNumber( 1 , 5000 );
		CryptedChar cChar;
		cChar._Key = Num;
		cChar.Letter = str[ i ] - cChar._Key;
		Result += ( str[ i ] - cChar._Key );
		cStr.EncryptedString.emplace_back( cChar );
	}

	Strings.emplace_back( cStr );
	SaveEncryptedStringsToFile( xorstr_( "crypt.txt" ) , cStr );
	return Result;
}

bool StringCrypt::CleanString( std::string * sPtr ) {
	std::fill( sPtr->begin( ) , sPtr->end( ) , 0 );
	delete sPtr;
	return true;
}

std::string * StringCrypt::DecryptString( std::string hash ) {

	for ( const auto & cStr : Strings ) {
		if ( cStr.Hash == hash ) {
			auto * result = new std::string;
			result->reserve( cStr.EncryptedString.size( ) ); // Pre-allocate memory

			for ( const auto & cChar : cStr.EncryptedString ) {
				result->push_back( cChar.Letter + cChar._Key );
			}
			return result;
		}
	}
	return nullptr;
}

std::string * StringCrypt::DecryptString( CryptedString str ) {
	auto * result = new std::string;
	result->reserve( str.EncryptedString.size( ) ); // Pre-allocate memory

	for ( const auto & cChar : str.EncryptedString ) {
		result += ( cChar.Letter + cChar._Key );
	}

	return result;
}

void StringCrypt::SaveEncryptedStringsToFile( std::string  filename , CryptedString cStr ) {
	std::ofstream file( filename );

	if ( !file.is_open( ) ) {
		return;
	}

	file << xorstr_( "Hash: " ) << cStr.Hash << "\n";
	file << xorstr_( "EncryptedString: \n" );
	for ( const auto & cChar : cStr.EncryptedString ) {
		file << xorstr_( "  Key: " ) << cChar._Key << xorstr_( " Letter: " ) << static_cast< int >( cChar.Letter ) << "\n";
	}
	file << "\n"; // Adiciona uma linha em branco entre cada string criptografada

	file.close( );
}