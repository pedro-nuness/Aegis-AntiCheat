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




void Utils::ColoredText( std::string text , COLORS color )
{
	HANDLE hConsole = GetStdHandle( STD_OUTPUT_HANDLE );
	SetConsoleTextAttribute( hConsole , color );
	std::cout << text;
	SetConsoleTextAttribute( hConsole , WHITE );
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

void Utils::Warn( COLORS color , std::string custom_text )
{
	std::string text = custom_text == ( "" ) ? ( "-" ) : custom_text;
	ColoredText( xorstr_( "[" ) , WHITE );
	ColoredText( text , color );
	ColoredText( xorstr_( "] " ) , WHITE );
}


void Utils::WarnMessage( COLORS color , std::string custom_text , std::string Message , COLORS _col ) {
	Warn( color , custom_text );
	ColoredText( xorstr_( " " ) + Message + xorstr_("\n" ) , _col );
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