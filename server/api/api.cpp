#define CURL_STATICLIB
#include <curl/curl.h>

#include "api.h"
#include "../utils/xorstr.h"
#include "../config/config.h"
#include "../log/log.h"
#include "../globals/globals.h" 

#include <iostream>

#include <time.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>


#include <nlohmann/json.hpp>

using json = nlohmann::json;


size_t WriteCallback( void * contents , size_t size , size_t nmemb , std::string * userp ) {
	size_t totalSize = size * nmemb;
	userp->append( static_cast< char * >( contents ) , totalSize );
	return totalSize;
}

enum class ApiAnswer {
	Success = 200 ,               // Sucesso
	None = 0 ,                    // Sem erro
	BadRequest = 400 ,            // Erro de requisição inválida
	Unauthorized = 403 ,          // Não autorizado
	NotFound = 404 ,              // Não encontrado
	InternalServerError = 500 ,   // Erro interno do servidor
	SubscriptionEnded = 301 ,
	InvalidApiKey ,               // Chave de API inválida
	InvalidJson ,                 // JSON inválido no corpo da requisição
	MissingHeaders ,              // Cabeçalhos ausentes
	UserNotFound ,                // Usuário não encontrado
	PasswordIncorrect ,           // Senha incorreta
	UnknownError                 // Erro desconhecido
};


bool Api::Login( std::string * buffer) {
	const std::string Apikey = config::Get( ).GetApiKey( );
	const std::string json_data = R"({"username": "admin", "password": "password"})";

	CURL * curl;
	CURLcode res;
	std::string readBuffer;

	long http_code = 0;

	curl = curl_easy_init( );
	if ( curl ) {
		// Configurações básicas da cURL
		curl_easy_setopt( curl , CURLOPT_URL , xorstr_( "https://353boacx50.execute-api.us-east-2.amazonaws.com/Production/login" ) );
		curl_easy_setopt( curl , CURLOPT_POST , 1L );
		curl_easy_setopt( curl , CURLOPT_POSTFIELDS , json_data.c_str( ) );

		// Definindo os cabeçalhos
		struct curl_slist * headers = NULL;

		headers = curl_slist_append( headers , xorstr_( "Content-Type: application/json" ) );
		headers = curl_slist_append( headers , ( xorstr_( "holder: " ) + config::Get( ).GetUsername( ) ).c_str( ) );

		{
			std::string temp_x_api_key = xorstr_( "x-api-key: " ) + config::Get( ).GetApiKey( );
			headers = curl_slist_append( headers , temp_x_api_key.c_str( ) );
			// Sobrescreve os dados na memória com zeros antes de liberar
			std::fill( temp_x_api_key.begin( ) , temp_x_api_key.end( ) , '\0' );
			temp_x_api_key.clear( );
		}
		{
			std::string temp_authorization = xorstr_( "authorization: vZ9Is52j3aXUSq7qgZWfH0oZwPNDzPr9" );
			headers = curl_slist_append( headers , temp_authorization.c_str( ) );

			std::fill( temp_authorization.begin( ) , temp_authorization.end( ) , '\0' );
			temp_authorization.clear( );
		}

		// Adicionando headers e configurando callback
		curl_easy_setopt( curl , CURLOPT_HTTPHEADER , headers );
		curl_easy_setopt( curl , CURLOPT_WRITEFUNCTION , WriteCallback );
		curl_easy_setopt( curl , CURLOPT_WRITEDATA , &readBuffer );

		// Executando a requisição
		res = curl_easy_perform( curl );

		if ( res != CURLE_OK ) {
			LogSystem::Get( ).LogWithMessageBox( xorstr_( "Error" ) , curl_easy_strerror( res ) );
		}

		curl_easy_getinfo( curl , CURLINFO_RESPONSE_CODE , &http_code );

		json js;

		try {
			js = json::parse( readBuffer );
		}
		catch ( const json::parse_error & e ) {
			std::cout << xorstr_( "Failed to parse JSON: " ) << e.what( ) << std::endl;
			return false;
		}


		switch ( ( ApiAnswer ) http_code ) {
		case ApiAnswer::Success:
			globals::Get( ).LoggedIn = true;
			break;
		default:
			LogSystem::Get( ).LogWithMessageBox( xorstr_( "Error" ) , js[ xorstr_( "message" ) ] );
			break;
		}

		if ( buffer != nullptr )
		{
			*buffer = js[ xorstr_( "message" ) ];
		}


		// Limpeza
		curl_slist_free_all( headers );
		curl_easy_cleanup( curl );
	}
	else {
		return false;
	}
	return true;
}
