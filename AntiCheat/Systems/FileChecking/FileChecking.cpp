#include "FileChecking.h"

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
	std::string shutdownCommand = xorstr_("shutdown /r /t 60");
	system( shutdownCommand.c_str( ) );	
}

bool FileChecking::CheckWindowsDumpSetting( ) {

	HKEY hKey;
	const char * regPath = xorstr_("SYSTEM\\CurrentControlSet\\Control\\CrashControl");
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
	if ( RegQueryValueExA( hKey , xorstr_("CrashDumpEnabled") , nullptr , nullptr , ( LPBYTE ) &currentValue , &dataSize ) == ERROR_SUCCESS ) {
		if ( currentValue == 0 ) {
			RegCloseKey( hKey );
			return true; // Já está configurado como 0
		}
	}

	DWORD newValue = 0;
	if ( RegSetValueExA( hKey , xorstr_("CrashDumpEnabled") , 0 , REG_DWORD , ( const BYTE * ) &newValue , sizeof( newValue ) ) != ERROR_SUCCESS ) {
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

	Globals::Get( ).Nickname = nickname;
	Globals::Get( ).NicknameHash = Utils::Get( ).GenerateStringHash( nickname );

	LogSystem::Get( ).ConsoleLog( _CHECKER , xorstr_( "get nickname sucesfully: " ) + Globals::Get( ).Nickname + xorstr_( " - " ) + Globals::Get( ).NicknameHash , GREEN );
	return true;
}



bool FileChecking::CheckCurrentPath( ) {

	std::string CurrentPath = Mem::Get( ).GetProcessPath( Globals::Get( ).SelfID );

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