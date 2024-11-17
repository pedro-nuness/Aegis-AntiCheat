#pragma once
#include "utils.h"
#include <iostream>
#include <Windows.h>
#include <random>
#include "xorstr.h"


#include <openssl/evp.h>
#include <openssl/sha.h>
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

#include <Wininet.h>
#pragma comment(lib, "wininet.lib")

bool Utils::ExistsFile( const std::string & name )
{
	if ( FILE * file = fopen( name.c_str( ) , "r" ) ) {
		fclose( file );
		return true;
	}
	else {
		return false;
	}
}



char * Utils::GenerateRandomString( int length ) //make sure to delete[] memory after
{
	if ( length == 0 )
		return NULL;

	const char charset[ ] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";

	char * randomString = new char[ ( length + 1 ) * sizeof( char ) ];

	srand( time( ( time_t * ) NULL ) );

	for ( int i = 0; i < length; ++i )
		randomString[ i ] = charset[ rand( ) % ( strlen( charset ) - 1 ) ];

	randomString[ length ] = '\0';

	return randomString;
}

wchar_t * Utils::GenerateRandomWString( int length ) //make sure to delete[] memory after
{
	if ( length == 0 )
		return NULL;

	const wchar_t charset[ ] = L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";

	wchar_t * randomString = new wchar_t[ ( length + 1 ) * sizeof( wchar_t ) ];

	srand( time( ( time_t * ) NULL ) );

	for ( int i = 0; i < length; ++i )
		randomString[ i ] = charset[ rand( ) % ( wcslen( charset ) - 1 ) ];

	randomString[ length ] = '\0';

	return randomString;
}


std::string Utils::GetRandomLetter( )
{
	std::string letters[ ] = { "a", "b", "c", "d", "e", "f", "g", "h", "i",
					"j", "k", "l", "m", "n", "o", "p", "q", "r",
					"s", "t", "u", "v", "w", "x", "y", "z", "A", "B", "C"
					"D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O"
					"P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z" };

	std::random_device r;
	std::seed_seq seed { r( ), r( ), r( ), r( ), r( ), r( ), r( ), r( ) };
	std::shuffle( std::begin( letters ) , std::end( letters ) ,
		std::mt19937( seed ) );

	for ( auto c : letters )
		return c;

}

std::string Utils::GetRandomWord( int size ) {

	std::string name;

	for ( int b = 0; b < size; b++ )
		name += GetRandomLetter( );

	return name;
}

bool Utils::isNumber( const std::string & str ) {
	// Handle empty string
	if ( str.empty( ) ) return false;

	// Handle negative numbers
	size_t start = ( str[ 0 ] == '-' ) ? 1 : 0;

	for ( size_t i = start; i < str.size( ); ++i ) {
		if ( !std::isdigit( str[ i ] ) ) return false;
	}

	return true;
}
std::string Utils::GenerateRandomKey( int size ) {

	std::string name;

	for ( int b = 0; b < size; b++ )
		name += GetRandomCharacter( );

	return name;
}

std::string Utils::GetRandomCharacter( ) {
	std::string letters[ ] = { "a", "b", "c", "d", "e", "f", "g", "h", "i",
					"j", "k", "l", "m", "n", "o", "p", "q", "r",
					"s", "t", "u", "v", "w", "x", "y", "z", "A", "B", "C"
					"D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O"
					"P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "0",
	"1", "2", "3", "4", "5", "6", "7", "8", "9", "!", "@", "#", "%","^", "&", "*", "(", ")",
	"_", "-", "+", "=", "?", ";", "'", "[", "]" };

	std::random_device r;
	std::seed_seq seed { r( ), r( ), r( ), r( ), r( ), r( ), r( ), r( ) };
	std::shuffle( std::begin( letters ) , std::end( letters ) ,
		std::mt19937( seed ) );

	for ( auto c : letters )
		return c;
}

bool Utils::CheckStrings( std::string bString1 , std::string bExpectedResult )
{
	size_t found = bString1.find( bExpectedResult );
	if ( found != std::string::npos )
	{
		return true;
	}

	return false;
}


bool Utils::encryptMessage( const std::string & plaintext , std::string & ciphertext , const std::string & key , const std::string & iv ) {
	EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new( );
	if ( !ctx ) {
		return false;
	}

	if ( 1 != EVP_EncryptInit_ex( ctx , EVP_aes_256_cbc( ) , NULL ,
		reinterpret_cast< const unsigned char * >( key.data( ) ) ,
		reinterpret_cast< const unsigned char * >( iv.data( ) ) ) ) {
		EVP_CIPHER_CTX_free( ctx );
		return false;
	}

	int len;
	int ciphertext_len;
	unsigned char outbuf[ 1024 ];

	if ( 1 != EVP_EncryptUpdate( ctx , outbuf , &len ,
		reinterpret_cast< const unsigned char * >( plaintext.data( ) ) , plaintext.length( ) ) ) {
		EVP_CIPHER_CTX_free( ctx );
		return false;
	}
	ciphertext_len = len;

	if ( 1 != EVP_EncryptFinal_ex( ctx , outbuf + len , &len ) ) {
		EVP_CIPHER_CTX_free( ctx );
		return false;
	}
	ciphertext_len += len;

	ciphertext.assign( reinterpret_cast< char * >( outbuf ) , ciphertext_len );

	EVP_CIPHER_CTX_free( ctx );
	return true;
}

// Função para descriptografar a mensagem usando AES-256-CBC
bool Utils::decryptMessage( const std::string & ciphertext , std::string & plaintext , const std::string & key , const std::string & iv ) {
	EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new( );
	if ( !ctx ) {
		std::cerr << xorstr_( "Failed to create context for decryption." ) << std::endl;
		return false;
	}

	if ( 1 != EVP_DecryptInit_ex( ctx , EVP_aes_256_cbc( ) , NULL , ( unsigned char * ) key.data( ) , ( unsigned char * ) iv.data( ) ) ) {
		std::cerr << xorstr_( "Decryption initialization failed." ) << std::endl;
		EVP_CIPHER_CTX_free( ctx );
		return false;
	}

	int len;
	int plaintext_len;
	unsigned char outbuf[ 1024 ];

	if ( 1 != EVP_DecryptUpdate( ctx , outbuf , &len , ( unsigned char * ) ciphertext.data( ) , ciphertext.length( ) ) ) {
		std::cerr << xorstr_( "Decryption failed." ) << std::endl;
		EVP_CIPHER_CTX_free( ctx );
		return false;
	}
	plaintext_len = len;

	if ( 1 != EVP_DecryptFinal_ex( ctx , outbuf + len , &len ) ) {
		std::cerr << xorstr_( "Final decryption step failed." ) << std::endl;
		EVP_CIPHER_CTX_free( ctx );
		return false;
	}
	plaintext_len += len;

	plaintext.assign( ( char * ) outbuf , plaintext_len );

	EVP_CIPHER_CTX_free( ctx );
	return true;
}


int Utils::RandomNumber( int min , int max )
{
	std::random_device rd;
	std::mt19937 rng( rd( ) );
	std::uniform_int_distribution<int> uni( min , max );
	return uni( rng );
}


std::string replaceAll( std::string subject , const std::string & search ,
	const std::string & replace ) {
	size_t pos = 0;
	while ( ( pos = subject.find( search , pos ) ) != std::string::npos ) {
		subject.replace( pos , search.length( ) , replace );
		pos += replace.length( );
	}
	return subject;
}

std::string Utils::DownloadString( std::string URL ) {
	HINTERNET interwebs = InternetOpenA( "Mozilla/5.0" , INTERNET_OPEN_TYPE_DIRECT , NULL , NULL , NULL );
	HINTERNET urlFile;
	std::string rtn;
	if ( interwebs ) {
		urlFile = InternetOpenUrlA( interwebs , URL.c_str( ) , NULL , NULL , NULL , NULL );
		if ( urlFile ) {
			char buffer[ 2000 ];
			DWORD bytesRead;
			do {
				InternetReadFile( urlFile , buffer , 2000 , &bytesRead );
				rtn.append( buffer , bytesRead );
				memset( buffer , 0 , 2000 );
			} while ( bytesRead );
			InternetCloseHandle( interwebs );
			InternetCloseHandle( urlFile );
			std::string p = replaceAll( rtn , "|n" , "\r\n" );
			return p;
		}
	}
	InternetCloseHandle( interwebs );
	std::string p = replaceAll( rtn , "|n" , "\r\n" );
	return p;
}