#include <iostream>

#include "File/File.h"

#include <openssl/sha.h>
#include <openssl/evp.h>

#include <string>
#include <vector>


#include <nlohmann/json.hpp>

using nlohmann::json;

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

std::vector<std::string> ReconstructString( std::vector<std::vector<int>> Lines ) {
	std::vector<std::string> Result;
	if ( Lines.empty( ) ) {
		return Result;
	}

	for ( int i = 0; i < Lines.size( ); i++ ) {
		std::string Line;
		for ( int j = 0; j < Lines.at( i ).size( ); j++ ) {
			Line += ( char ) Lines.at( i ).at( j );
		}
		Result.emplace_back( Line );
	}
}

int main( int argc , char * argv[ ] ) {

	if ( argc <= 1 )
		return 0;


	std::string InputFilePath = argv[ 1 ];
	File InputFile( argv[ 1 ] );
	if ( !InputFile.Exists( ) )
		return 0;

	std::string JsonFromFile = InputFile.Read( );

	json js;
	try {
		js = json::parse( JsonFromFile );
	}
	catch ( json::parse_error error ) {
		std::cout << "Failed to parse json!\n";
		system( "pause" );
		return false;
	}
	std::string IV , FinalLog;

	std::vector<std::vector<int>> EncryptedLines;

	IV = js[ "IV" ];
	FinalLog = js[ "Final" ];
	EncryptedLines = js[ "Log" ];


	std::vector<std::string> ReconstructedLog = ReconstructString( EncryptedLines );


	File OutputFile( "output.txt" );
	OutputFile.Create( );
	for ( int i = 0; i < ReconstructedLog.size( ); i++ ) {
		std::string DecryptedLine;
		if ( !decryptMessage( ReconstructedLog.at( i ) , DecryptedLine , log_key , IV ) ) {
			std::cout << "Failed on " << i << std::endl;
			system( "pause" );
			return 0;
		}
		OutputFile.Write( DecryptedLine );
	}
	OutputFile.Write( FinalLog );


	return 1;
}