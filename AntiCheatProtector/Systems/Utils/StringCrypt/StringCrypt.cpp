#include <iostream>
#include <thread>
#include <fstream>

#include "StringCrypt.h"
#include "../utils.h"
#include "../xorstr.h"
#include "../../Memory/memory.h"
#include "../SHA1/sha1.h"


void StringCrypt::Init( ) {
	CryptedString cStr;
	cStr.Hash = xorstr_( "90ed071b4c6ba84ada3b57733b60bc092c758930" );
	cStr.EncryptedString = {
		{4176, -38}, {1570, 41}, {4970, -8}, {1242, 104}, {557, 43},
		{4416, 18}, {3709, -40}, {3245, -122}, {1602, 7}, {1617, -9},
		{601, -3}, {2798, 88}, {4596, -124}, {1880, -50}, {988, -101},
		{4880, 99}, {1466, 127}, {4099, 52}, {4802, 99}, {3078, 106},
		{2648, -20}, {3669, -29}, {4682, -9}, {215, 91}, {3252, -106},
		{2183, -55}, {1732, -119}, {4131, 5}, {3064, 117}, {4784, -58}
	};

	Strings.emplace_back( cStr );
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
	SaveEncryptedStringsToFile( xorstr_( "crypt.txt" ) );
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

void StringCrypt::SaveEncryptedStringsToFile( std::string  filename ) {
	std::ofstream file( filename );

	if ( !file.is_open( ) ) {
		return;
	}

	for ( const auto & cStr : Strings ) {
		file << xorstr_( "Hash: " ) << cStr.Hash << "\n";
		file << xorstr_( "EncryptedString: \n" );
		for ( const auto & cChar : cStr.EncryptedString ) {
			file << xorstr_( "  Key: " ) << cChar._Key << xorstr_( " Letter: " ) << static_cast< int >( cChar.Letter ) << "\n";
		}
		file << "\n"; // Adiciona uma linha em branco entre cada string criptografada
	}

	file.close( );
}