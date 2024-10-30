#include "utils.h"
#include <iostream>
#include <sstream>
#include <random>


#include "xorstr.h"

#include <openssl/evp.h>
#include <openssl/sha.h>
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

#include <mutex>


std::string utils::GenerateHash( const std::vector<BYTE> & input )
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

bool utils::CheckStrings( std::string bString1 , std::string bExpectedResult )
{
	size_t found = bString1.find( bExpectedResult );
	if ( found != std::string::npos )
	{
		return true;
	}

	return false;
}

void utils::Warn( COLORS color , std::string custom_text )
{
	std::string text = custom_text == ( "" ) ? ( "-" ) : custom_text;
	ColoredText( xorstr_( "[" ) , WHITE );
	ColoredText( text , color );
	ColoredText( xorstr_( "] " ) , WHITE );
}

std::mutex PrintMutex;

void utils::WarnMessage( MODULE_SENDER sender , std::string Message , COLORS _col ) {

#if false
	return;
#else
	std::lock_guard<std::mutex> lock( PrintMutex );  // Protege o acesso a ConnectionMap

	std::string custom_text = xorstr_( "undefined" );
	COLORS custom_col = RED;

	switch ( sender ) {
	case _SENDER:
		custom_text = xorstr_( "sender" );
		custom_col = LIGHT_RED;
		break;
	case _SERVER:
		custom_text = xorstr_( "server" );
		custom_col = LIGHT_BLUE;
		break;
	case WEBHOOK:
		custom_text = xorstr_( "discord bot" );
		custom_col = BLUE;
		break;
	}

	Warn( custom_col , custom_text );
	ColoredText( xorstr_( " " ) + Message + xorstr_( "\n" ) , _col );
#endif
}


//void utils::WarnMessage( COLORS color , std::string custom_text , std::string Message , COLORS _col ) {
//	std::lock_guard<std::mutex> lock( PrintMutex );
//	Warn( color , custom_text );
//	ColoredText( xorstr_( " " ) + Message + xorstr_( "\n" ) , _col );
//}



void utils::ColoredText( std::string text , COLORS color )
{
	HANDLE hConsole = GetStdHandle( STD_OUTPUT_HANDLE );
	SetConsoleTextAttribute( hConsole , color );
	std::cout << text;
	SetConsoleTextAttribute( hConsole , WHITE );
}

bool utils::encryptMessage( const std::string & plaintext , std::string & ciphertext , const std::string & key , const std::string & iv ) {
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
bool utils::decryptMessage( const std::string & ciphertext , std::string & plaintext , const std::string & key , const std::string & iv ) {
	EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new( );
	if ( !ctx ) {
		std::cerr << xorstr_("Failed to create context for decryption.") << std::endl;
		return false;
	}

	if ( 1 != EVP_DecryptInit_ex( ctx , EVP_aes_256_cbc( ) , NULL , ( unsigned char * ) key.data( ) , ( unsigned char * ) iv.data( ) ) ) {
		std::cerr << xorstr_( "Decryption initialization failed.") << std::endl;
		EVP_CIPHER_CTX_free( ctx );
		return false;
	}

	int len;
	int plaintext_len;
	unsigned char outbuf[ 1024 ];

	if ( 1 != EVP_DecryptUpdate( ctx , outbuf , &len , ( unsigned char * ) ciphertext.data( ) , ciphertext.length( ) ) ) {
		std::cerr << xorstr_( "Decryption failed.") << std::endl;
		EVP_CIPHER_CTX_free( ctx );
		return false;
	}
	plaintext_len = len;

	if ( 1 != EVP_DecryptFinal_ex( ctx , outbuf + len , &len ) ) {
		std::cerr << xorstr_( "Final decryption step failed.") << std::endl;
		EVP_CIPHER_CTX_free( ctx );
		return false;
	}
	plaintext_len += len;

	plaintext.assign( ( char * ) outbuf , plaintext_len );

	EVP_CIPHER_CTX_free( ctx );
	return true;
}

std::string utils::GetRandomCharacter( ) {
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

std::string utils::GenerateRandomKey( int size ) {

	std::string name;

	for ( int b = 0; b < size; b++ )
		name += GetRandomCharacter( );

	return name;
}

std::string utils::GetRandomLetter( )
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

std::string utils::GetRandomWord( int size ) {

	std::string name;

	for ( int b = 0; b < size; b++ )
		name += GetRandomLetter( );

	return name;
}