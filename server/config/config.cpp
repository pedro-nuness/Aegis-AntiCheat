#include "config.h"
#include <windows.h>
#include "../utils/xorstr.h"
#include "../utils/File/File.h"
#include <nlohmann/json.hpp>
#include <unordered_map>

using json = nlohmann::json;


// Função auxiliar para exibir mensagens de erro e encerrar
void ShowErrorAndExit( const std::string & errorMessage ) {
	// Determinar o tamanho necessário para a string wide
	int sizeNeeded = MultiByteToWideChar( CP_UTF8 , 0 , errorMessage.c_str( ) , -1 , NULL , 0 );
	std::wstring wideMessage( sizeNeeded , 0 );
	// Converter a string
	MultiByteToWideChar( CP_UTF8 , 0 , errorMessage.c_str( ) , -1 , &wideMessage[ 0 ] , sizeNeeded );

	MessageBoxW( NULL , wideMessage.c_str( ) , L"Error" , MB_OK | MB_ICONWARNING );
	exit( 0 );
}

// Funções auxiliares de validação de tipos
bool is_number( const json & j ) {
	return j.is_number( );
}

bool is_string( const json & j ) {
	return j.is_string( );
}

void config::LoadConfig( ) {
	File ConfigFile( xorstr_( "config.json" ) );

	json DefaultConfig = {
		{ xorstr_( "PingTolerance" ), 0 },
		{ xorstr_( "ApiKey" ), "" },
		{ xorstr_( "Username" ), "" },
		{ xorstr_( "DiscordChannel" ), 0 },
		{ xorstr_( "BotToken" ), "" },
		{ xorstr_( "ServerPort" ), 0 }
	};

	// Verifica se o arquivo de configuração existe
	if ( !ConfigFile.Exists( ) ) {
		ConfigFile.Create( );
		ConfigFile.Write( DefaultConfig.dump( ) );
		ShowErrorAndExit( xorstr_( "Server not configured, please check config.json" ) );
	}

	std::string FileContent = ConfigFile.Read( );

	// Verifica se o arquivo de configuração está vazio
	if ( FileContent.empty( ) ) {
		ConfigFile.Write( DefaultConfig.dump( ) );
		ShowErrorAndExit( xorstr_( "config.json is empty, please configure the server!" ) );
	}

	json Config;
	try {
		Config = json::parse( FileContent );
	}
	catch ( const json::parse_error & ) {
		ConfigFile.Clear( );
		ConfigFile.Write( DefaultConfig.dump( ) );
		ShowErrorAndExit( xorstr_( "Failed to parse config.json content!" ) );
	}

	// Mapa de validações: campo -> função de validação
	std::unordered_map<std::string , bool( * )( const json & )> validations = {
		{ xorstr_( "PingTolerance" ), is_number },
		{ xorstr_( "ApiKey" ), is_string },
		{ xorstr_( "DiscordChannel" ), is_number },
		{ xorstr_( "BotToken" ), is_string },
		{ xorstr_( "Username" ), is_string },
		{ xorstr_( "ServerPort" ), is_number }
	};

	// Loop para validar os campos obrigatórios
	for ( const auto & [field , validate] : validations ) {
		if ( !Config.contains( field ) || !validate( Config[ field ] ) ) {
			std::string errorMessage = xorstr_( "Invalid or missing field: " ) + field;
			ShowErrorAndExit( errorMessage );
		}
	}

	// Carregar as configurações no objeto
	this->PingTolerance = Config[ xorstr_( "PingTolerance" ) ];
	this->ApiKey = Config[ xorstr_( "ApiKey" ) ];
	this->BotToken = Config[ xorstr_( "BotToken" ) ];
	this->DiscordChannel = Config[ xorstr_( "DiscordChannel" ) ];
	this->Username = Config[ xorstr_( "Username" ) ];
	this->CapturePort = Config[ xorstr_( "ServerPort" ) ];
}
