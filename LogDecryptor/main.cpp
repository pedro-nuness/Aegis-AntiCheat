#include <iostream>

#include "File/File.h"

#include <openssl/sha.h>
#include <openssl/evp.h>

#include <string>
#include <vector>

std::string removeNonAlphanumeric( const std::string & input ) {
	std::string result = input;
	// Remove caracteres que não sejam alfanuméricos
	result.erase( std::remove_if( result.begin( ) , result.end( ) ,
		[ ] ( unsigned char c ) { return !std::isalnum( c ); } ) , result.end( ) );
	return result;
}

bool decryptMessage( const std::string & ciphertext , std::string & plaintext , const std::string & key , const std::string & iv ) {
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

#define log_key "fmu843q0fpgonamgfjkang08fgd94qgn"

int main( int argc , char * argv[ ] ) {

	if ( argc <= 1 )
		return 0;

	int FileLines = 0;

	std::string InputFilePath = argv[ 1 ];
	File InputFile( argv[ 1 ] );
	if ( !InputFile.Exists( ) )
		return 0;

	if ( argc > 2 )
		FileLines = std::stoi(argv[ 2 ]);

	std::string IV , FinalLog;

	std::vector<std::string> EncryptedLines;

	if(!FileLines )
		FileLines = InputFile.GetNumLines( );

	std::cout << "File lines: " << FileLines << std::endl;

	for ( int i = 1; i <= FileLines; i++ ) {
		std::string Line = InputFile.ReadLine( i );

		if ( i == 1 ) {
			Line.erase( std::remove( Line.begin( ) , Line.end( ) , '\n' ) , Line.end( ) );
			IV = Line;
			std::cout << "iv: " << IV << "\n";
			continue;
		}
		if ( i == FileLines ) {
			Line.erase( std::remove( Line.begin( ) , Line.end( ) , '\n' ) , Line.end( ) );
			FinalLog = Line;
			std::cout << "Final: " << FinalLog << "\n";
			continue;
		}

		Line.erase( Line.size( ) - 1 );
		EncryptedLines.emplace_back( Line );
	}


	File OutputFile( "output.txt" );
	OutputFile.Create( );
	OutputFile.Write( IV );
	for ( int i = 0; i < EncryptedLines.size( ); i++ ) {
		std::string DecryptedLine;
		if ( !decryptMessage( EncryptedLines.at( i ) , DecryptedLine , log_key , IV ) ) {
			std::cout << "Failed on " << i << std::endl;
			system( "pause" );
			return 0;
		}
		OutputFile.Write( DecryptedLine );
	}
	OutputFile.Write( FinalLog );


	return 1;
}