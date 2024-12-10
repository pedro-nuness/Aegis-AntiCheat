#pragma once
#include "utils.h"
#include <iostream>
#include <Windows.h>
#include <random>
#include "xorstr.h"
#include <mutex>

#include <openssl/sha.h>
#include <openssl/evp.h>

#include <sstream>

#include "../../Globals/Globals.h"

#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

#include <Wininet.h>
#pragma comment(lib, "wininet.lib")


std::string Utils::GenerateHash( const std::vector<BYTE> & input )
{
	unsigned char hash[ SHA256_DIGEST_LENGTH ];
	SHA256_CTX sha256;
	SHA256_Init( &sha256 );
	SHA256_Update( &sha256 , input.data( ) , input.size( ) );
	SHA256_Final( hash , &sha256 );

	std::ostringstream oss;
	for ( int i = 0; i < SHA256_DIGEST_LENGTH; ++i )
	{
		oss << std::hex << ( int ) hash[ i ];
	}

	return oss.str( );
}

std::string Utils::GenerateStringHash( const std::string & input )
{
	unsigned char hash[ SHA256_DIGEST_LENGTH ];
	SHA256_CTX sha256;
	SHA256_Init( &sha256 );
	SHA256_Update( &sha256 , input.data( ) , input.size( ) );
	SHA256_Final( hash , &sha256 );

	std::ostringstream oss;
	for ( int i = 0; i < SHA256_DIGEST_LENGTH; ++i )
	{
		oss << std::hex << ( int ) hash[ i ];
	}

	return oss.str( );
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


std::vector<unsigned char> Utils::DownloadFileToMemory( const std::string & url ) {
	std::vector<unsigned char> buffer;
	HINTERNET hInternet = nullptr , hConnect = nullptr;
	DWORD bytesRead = 0;

	// Initialize WinINet
	hInternet = InternetOpen( "WinINet Example" , INTERNET_OPEN_TYPE_DIRECT , NULL , NULL , 0 );
	if ( !hInternet ) {
		std::cerr << "InternetOpen failed." << std::endl;
		return buffer;
	}

	// Open URL
	hConnect = InternetOpenUrl( hInternet , url.c_str( ) , NULL , 0 , INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE , 0 );
	if ( !hConnect ) {
		std::cerr << "InternetOpenUrl failed." << std::endl;
		InternetCloseHandle( hInternet );
		return buffer;
	}

	// Read data from the URL
	unsigned char tempBuffer[ 4096 ];
	while ( InternetReadFile( hConnect , tempBuffer , sizeof( tempBuffer ) , &bytesRead ) && bytesRead != 0 ) {
		buffer.insert( buffer.end( ) , tempBuffer , tempBuffer + bytesRead );
	}

	// Clean up
	InternetCloseHandle( hConnect );
	InternetCloseHandle( hInternet );

	return buffer;
}


// Função para descriptografar a mensagem usando AES-256-CBC
bool Utils::decryptMessage( const std::string & ciphertext , std::string & plaintext , const std::string & key , const std::string & iv ) {
	EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new( );
	if ( !ctx ) {
		std::cerr << "Failed to create context for decryption." << std::endl;
		return false;
	}

	if ( 1 != EVP_DecryptInit_ex( ctx , EVP_aes_256_cbc( ) , NULL , ( unsigned char * ) key.data( ) , ( unsigned char * ) iv.data( ) ) ) {
		std::cerr << "Decryption initialization failed." << std::endl;
		EVP_CIPHER_CTX_free( ctx );
		return false;
	}

	int len;
	int plaintext_len;
	unsigned char outbuf[ 1024 ];

	if ( 1 != EVP_DecryptUpdate( ctx , outbuf , &len , ( unsigned char * ) ciphertext.data( ) , ciphertext.length( ) ) ) {
		std::cerr << "Decryption failed." << std::endl;
		EVP_CIPHER_CTX_free( ctx );
		return false;
	}
	plaintext_len = len;

	if ( 1 != EVP_DecryptFinal_ex( ctx , outbuf + len , &len ) ) {
		std::cerr << "Final decryption step failed." << std::endl;
		EVP_CIPHER_CTX_free( ctx );
		return false;
	}
	plaintext_len += len;

	plaintext.assign( ( char * ) outbuf , plaintext_len );

	EVP_CIPHER_CTX_free( ctx );
	return true;
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

std::string Utils::GenerateRandomKey( int size ) {

	std::string name;

	for ( int b = 0; b < size; b++ )
		name += GetRandomCharacter( );

	return name;
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



bool Utils::CheckStrings( std::string bString1 , std::string bExpectedResult )
{
	size_t found = bString1.find( bExpectedResult );
	if ( found != std::string::npos )
	{
		return true;
	}

	return false;
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

std::string Utils::ConvertLPCWSTRToString( LPCWSTR wideString ) {
	if ( wideString == nullptr ) {
		return xorstr_( "" );  // Retorna uma string vazia se o ponteiro for nulo
	}

	int bufferSize = WideCharToMultiByte( CP_UTF8 , 0 , wideString , -1 , nullptr , 0 , nullptr , nullptr );
	std::string convertedString( bufferSize , 0 );

	WideCharToMultiByte( CP_UTF8 , 0 , wideString , -1 , &convertedString[ 0 ] , bufferSize , nullptr , nullptr );

	return convertedString;
}


bool Utils::DownloadToBuffer( const std::string & URL , std::vector<char> & buffer ) {
	HINTERNET interwebs = InternetOpenA( "Mozilla/5.0" , INTERNET_OPEN_TYPE_DIRECT , NULL , NULL , NULL );
	if ( !interwebs ) {
		return false;
	}

	HINTERNET urlFile = InternetOpenUrlA( interwebs , URL.c_str( ) , NULL , NULL , NULL , NULL );
	if ( !urlFile ) {
		InternetCloseHandle( interwebs );
		return false;
	}

	const DWORD chunkSize = 4096; // Tamanho do bloco a ser lido a cada operação
	std::vector<char> tempBuffer( chunkSize ); // Buffer temporário
	DWORD bytesRead;
	buffer.clear( );

	do {
		if ( !InternetReadFile( urlFile , tempBuffer.data( ) , tempBuffer.size( ) , &bytesRead ) ) {
			InternetCloseHandle( urlFile );
			InternetCloseHandle( interwebs );
			return false; // Falha ao ler
		}
		buffer.insert( buffer.end( ) , tempBuffer.begin( ) , tempBuffer.begin( ) + bytesRead );
	} while ( bytesRead > 0 );

	InternetCloseHandle( urlFile );
	InternetCloseHandle( interwebs );
	return true;
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