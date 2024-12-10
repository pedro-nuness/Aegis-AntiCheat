#include "FileChecking.h"


#include "../Hardware/hardware.h"

#include "../Memory/memory.h"
#include "../Utils/utils.h"
#include "../Utils/xorstr.h"
#include "../../Globals/Globals.h"

#include "../LogSystem/File/File.h"
#include "../LogSystem/log.h"

#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;

#define DUMPER_HASH xorstr_("")
#define CLIENT_HASH xorstr_("")

bool FileChecking::isGameValid( std::string GameName ) {

	return true;
}

std::string removeNonAlphanumeric( const std::string & input ) {
	std::string result = input;
	// Remove caracteres que não sejam alfanuméricos
	result.erase( std::remove_if( result.begin( ) , result.end( ) ,
		[ ] ( unsigned char c ) { return !std::isalnum( c ); } ) , result.end( ) );
	return result;
}

void ScheduleShutdown( ) {
	std::string shutdownCommand = xorstr_( "shutdown /r /t 60" );
	system( shutdownCommand.c_str( ) );
}

bool FileChecking::CheckWindowsDumpSetting( ) {

	HKEY hKey;
	const char * regPath = xorstr_( "SYSTEM\\CurrentControlSet\\Control\\CrashControl" );
	DWORD currentValue = 0;
	DWORD dataSize = sizeof( currentValue );

	if ( RegOpenKeyExA( HKEY_LOCAL_MACHINE , regPath , 0 , KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_64KEY , &hKey ) != ERROR_SUCCESS ) {
		return false;
	}
	// Valores possíveis para CrashDumpEnabled:
	// 0 = Nenhum
	// 1 = Pequeno
	// 2 = Kernel
	// 3 = Completo
	// 7 = Automático
	if ( RegQueryValueExA( hKey , xorstr_( "CrashDumpEnabled" ) , nullptr , nullptr , ( LPBYTE ) &currentValue , &dataSize ) == ERROR_SUCCESS ) {
		if ( currentValue == 0 ) {
			RegCloseKey( hKey );
			return true;
		}
	}

	DWORD newValue = 0;
	if ( RegSetValueExA( hKey , xorstr_( "CrashDumpEnabled" ) , 0 , REG_DWORD , ( const BYTE * ) &newValue , sizeof( newValue ) ) != ERROR_SUCCESS ) {
		RegCloseKey( hKey );
		ScheduleShutdown( );
		LogSystem::Get( ).LogWithMessageBox( xorstr_( "Dump disable" ) , xorstr_( "Reinicio necessario, reiniciando computador em 1 minuto!" ) );
		return false; 
	}

	RegCloseKey( hKey );
	return false;
}


bool FileChecking::GetNickname( ) {
	File nick_file( xorstr_( "nickname.ini" ) );
	if ( !nick_file.Exists( ) ) {
		LogSystem::Get( ).ConsoleLog( _CHECKER , xorstr_( "can't find nickname file!" ) , RED );
		return false;
	}

	std::string nickname = nick_file.Read( );
	nickname = removeNonAlphanumeric( nickname );

	auto Find = nickname.find( "\n" );

	if ( nickname.empty( ) ) {
		LogSystem::Get( ).ConsoleLog( _CHECKER , xorstr_( "nickname is empty" ) , RED );
		return false;
	}

	_globals.Nickname = nickname;
	_globals.NicknameHash = Utils::Get( ).GenerateStringHash( nickname );

	LogSystem::Get( ).ConsoleLog( _CHECKER , xorstr_( "get nickname sucesfully: " ) + _globals.Nickname + xorstr_( " - " ) + _globals.NicknameHash , GREEN );
	return true;
}



// Função para abrir ou criar a chave principal
HKEY OpenOrCreateKey( LPCSTR keyPath ) {
	HKEY hKey;
	LONG result = RegCreateKeyEx(
		HKEY_LOCAL_MACHINE ,        // Chave raiz
		keyPath ,                   // Caminho da chave
		0 ,                         // Reservado
		NULL ,                      // Classe (opcional)
		REG_OPTION_NON_VOLATILE ,   // Opções
		KEY_READ | KEY_WRITE ,      // Acesso desejado
		NULL ,                      // Atributos de segurança
		&hKey ,                     // Handle da chave criada ou aberta
		NULL                       // Valor de disposição (opcional)
	);

	if ( result != ERROR_SUCCESS ) {
		return nullptr;
	}

	return hKey;
}

// Função para verificar se um valor existe
bool ValueExists( HKEY hKey , LPCSTR valueName ) {
	LONG result = RegQueryValueEx(
		hKey ,                // Handle da chave
		valueName ,           // Nome do valor
		NULL ,                // Reservado
		NULL ,                // Tipo do valor (opcional)
		NULL ,                // Buffer para os dados (opcional)
		NULL                 // Tamanho do buffer (opcional)
	);

	return ( result == ERROR_SUCCESS );
}

// Função para criar ou definir um valor
bool CreateOrSetValue( HKEY hKey , LPCSTR valueName , DWORD valueData ) {
	LONG result = RegSetValueEx(
		hKey ,                        // Handle da chave
		valueName ,                   // Nome do valor
		0 ,                           // Reservado
		REG_DWORD ,                   // Tipo do valor
		reinterpret_cast< BYTE * >( &valueData ) , // Dados do valor
		sizeof( valueData )            // Tamanho dos dados
	);

	return result == ERROR_SUCCESS;
}

// Função para ler o valor existente
void ReadValue( HKEY hKey , LPCSTR valueName ) {
	DWORD valueData;
	DWORD dataSize = sizeof( valueData );
	LONG result = RegQueryValueEx(
		hKey ,                        // Handle da chave
		valueName ,                   // Nome do valor
		NULL ,                        // Reservado
		NULL ,                        // Tipo do valor (opcional)
		reinterpret_cast< BYTE * >( &valueData ) , // Buffer para os dados
		&dataSize                    // Tamanho do buffer
	);

	if ( result == ERROR_SUCCESS ) {
		std::wcout << L"Valor existente: " << valueName << L" = " << valueData << std::endl;
		system( "pause" );
	}
	else {
		std::cerr << "Falha ao ler o valor. Código de erro: " << result << std::endl;
	}
}


// Função para criar ou definir uma string como valor
bool CreateOrSetStringValue( HKEY hKey , LPCSTR valueName , LPCSTR valueData ) {
	LONG result = RegSetValueEx(
		hKey ,                        // Handle da chave
		valueName ,                   // Nome do valor
		0 ,                           // Reservado
		REG_SZ ,                      // Tipo do valor (REG_SZ para string)
		reinterpret_cast< const BYTE * >( valueData ) , // Dados do valor
		( strlen( valueData ) + 1 ) * sizeof( char ) // Tamanho dos dados (em bytes)
	);

	return result == ERROR_SUCCESS;
}

// Função para ler o valor existente (string)
bool ReadStringValue( HKEY hKey , LPCSTR valueName , std::string * buffer ) {
	char valueData[ 1024 ];
	DWORD dataSize = sizeof( valueData );
	LONG result = RegQueryValueEx(
		hKey ,                        // Handle da chave
		valueName ,                   // Nome do valor
		NULL ,                        // Reservado
		NULL ,                        // Tipo do valor (opcional)
		reinterpret_cast< BYTE * >( valueData ) , // Buffer para os dados
		&dataSize                    // Tamanho do buffer
	);

	if ( result == ERROR_SUCCESS ) {
		if ( buffer != nullptr )
			*buffer = valueData;
		return true;
	}

	return false;
}

#define regedit_key xorstr_("bfdgsam8fij2oijhu31q1sd3nhfamok8") // 32 bytes para AES-256
#define regedit_iv xorstr_("gui931dasijvmda0") // 16 bytes para AES

bool RequireValues( HKEY hKey , LPCSTR GUID , LPCSTR Authenticator ) {
	std::string GUIDStr;
	std::string AuthenticatorStr;

	if ( !ReadStringValue( hKey , GUID , &GUIDStr ) ) {
		return false;
	}

	if ( !ReadStringValue( hKey , Authenticator , &AuthenticatorStr ) ) {
		return false;
	}

	if ( !Utils::Get( ).decryptMessage( GUIDStr , GUIDStr , regedit_key , regedit_iv ) ) {
		return false;
	}

	if ( !Utils::Get( ).decryptMessage( AuthenticatorStr , AuthenticatorStr , regedit_key , regedit_iv ) ) {
		return false;
	}

	std::string Hash = Utils::Get( ).GenerateStringHash( GUIDStr );

	if ( strcmp( Hash.c_str( ) , AuthenticatorStr.c_str( ) ) ) {
		return false;
	}

	if ( !hardware::Get( ).GetUniqueUID( nullptr , GUIDStr ) ) {
		return false;
	}

	return true;
}

bool CreateFiles( HKEY hKey , LPCSTR GUID , LPCSTR Authenticator ) {
	char * RandString = Utils::Get( ).GenerateRandomString( 256 );
	std::string RandStringHash = Utils::Get( ).GenerateStringHash( RandString );
	std::string EncryptedRandomString = "";
	std::string EncryptedRandomStrinHash = "";
	Utils::Get( ).encryptMessage( RandString , EncryptedRandomString , regedit_key , regedit_iv );
	Utils::Get( ).encryptMessage( RandStringHash , EncryptedRandomStrinHash , regedit_key , regedit_iv );
	delete[ ] RandString;

	// Criar o valor
	CreateOrSetStringValue( hKey , GUID , EncryptedRandomString.c_str( ) );
	CreateOrSetStringValue( hKey , Authenticator , EncryptedRandomStrinHash.c_str( ) );

	return true;
}

bool FileChecking::UpdateRegValues( ) {
	LPCSTR keyPath = xorstr_( "SYSTEM\\CurrentControlSet\\Services\\AegisAntiCheat" );
	LPCSTR GUIDValue = xorstr_( "GUID" );
	LPCSTR GUIDAuthenticator = xorstr_( "GUIDAuthenticator" );

	// Abrir ou criar a chave principal
	HKEY hKey = OpenOrCreateKey( keyPath );
	if ( !hKey ) return false;

	// Verificar se o valor existe
	if ( ValueExists( hKey , GUIDValue ) ) {
		// Ler o valor existente
		if ( !RequireValues( hKey , GUIDValue , GUIDAuthenticator ) )
			return false;
	}
	else
	{
		if ( !CreateFiles( hKey , GUIDValue , GUIDAuthenticator ) )
			return false;

		if ( !RequireValues( hKey , GUIDValue , GUIDAuthenticator ) )
			return false;

	}

	// Fechar a chave
	RegCloseKey( hKey );
	return true;
}




bool FileChecking::CheckCurrentPath( ) {

	std::string CurrentPath = Mem::Get( ).GetProcessPath( _globals.SelfID );

	if ( CurrentPath.empty( ) ) {
		LogSystem::Get( ).ConsoleLog( _CHECKER , xorstr_( "failed to get path" ) , RED );
		return true;
	}

	if ( !fs::exists( xorstr_( "ACLogs" ) ) )
		fs::create_directory( xorstr_( "ACLogs" ) );

	try {
		std::vector<std::string> SearchStrings {
			xorstr_( ".i64" ),
			xorstr_( ".ida" )
		};

		if ( fs::exists( CurrentPath ) && fs::is_directory( CurrentPath ) ) {
			LogSystem::Get( ).ConsoleLog( _CHECKER , xorstr_( "scanning " ) + CurrentPath , RED );

			for ( const auto & entry : fs::directory_iterator( CurrentPath ) ) {
				try {
					for ( const std::string & name : SearchStrings ) {
						if ( Utils::Get( ).CheckStrings( entry.path( ).filename( ).string( ) , name ) ) {
							LogSystem::Get( ).ConsoleLog( _CHECKER , entry.path( ).filename( ).string( ) , YELLOW );
						}
					}
				}
				catch ( const std::filesystem::filesystem_error & ex ) {
					LogSystem::Get( ).ConsoleLog( _CHECKER , xorstr_( "Error processing file: " ) + entry.path( ).filename( ).string( ) , RED );
					continue;  // Se ocorrer erro em um arquivo, continua para o próximo
				}
			}
		}
		else {
			LogSystem::Get( ).ConsoleLog( _CHECKER , xorstr_( "invalid directory: " ) + CurrentPath , RED );
			LogSystem::Get( ).Log( xorstr_( "[02] Invalid directory" ) );
			return false;
		}
	}
	catch ( const std::filesystem::filesystem_error & ex ) {
		LogSystem::Get( ).ConsoleLog( _CHECKER , xorstr_( "unexpected error" ) , RED );
		LogSystem::Get( ).Log( xorstr_( "[03] unexpected error" ) );
	}

	return true;
}


bool FileChecking::CheckHash( ) {


	return true;
}


bool FileChecking::ValidateFiles( ) {

	if ( !this->UpdateRegValues( ) )
		return false;

	if ( !this->CheckWindowsDumpSetting( ) )
		return false;

	if ( !this->GetNickname( ) )
		return false;

	if ( !this->CheckCurrentPath( ) )
		return false;

	if ( !this->CheckHash( ) )
		return false;


	return true;
}