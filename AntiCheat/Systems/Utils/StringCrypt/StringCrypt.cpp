#include <fstream>
#include "StringCrypt.h"
#include "../utils.h"
#include "../xorstr.h"
#include "../../Memory/memory.h"
#include "../SHA1/sha1.h"
#include "../AES/AES.h"



void StringCrypt::Init( ) {

}

std::vector<char> StringCrypt::GeneratePlain( std::string str ) {
	std::vector<char> Plain;

	for ( auto c : str ) {
		Plain.emplace_back( c );
	}
	return Plain;
}


CryptedString StringCrypt::EncryptString( std::string str ) {

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

	cStr.Hash = Hash;

	return cStr;
}

bool StringCrypt::CleanString( std::string * sPtr ) {
	std::fill( sPtr->begin( ) , sPtr->end( ) , '\0' );
	delete sPtr;
	return true;
}


std::string * StringCrypt::DecryptString( CryptedString str ) {
	auto * result = new std::string;
	result->reserve( str.EncryptedString.size( ) ); // Pre-allocate memory

	for ( const auto & cChar : str.EncryptedString ) {
		result->push_back( cChar.Letter + cChar._Key );
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
	file << xorstr_("\n"); // Adiciona uma linha em branco entre cada string criptografada

	file.close( );
}