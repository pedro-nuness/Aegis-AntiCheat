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

bool FileChecking::GetNickname( ) {
	File nick_file( xorstr_( "nickname.ini" ) );
	if ( !nick_file.Exists( ) ) {
		Utils::Get( ).WarnMessage( _CHECKER , xorstr_( "can't find nickname file!" ) , RED );
		return false;
	}

	std::string nickname = nick_file.Read( );

	if ( nickname.empty( ) ) {
		Utils::Get( ).WarnMessage( _CHECKER , xorstr_( "nickname is empty" ) , RED );
		return false;
	}
	
	Globals::Get( ).Nickname = nickname;
	Globals::Get( ).NicknameHash = Utils::Get( ).GenerateStringHash( nickname );

	Utils::Get( ).WarnMessage( _CHECKER , xorstr_( "get nickname sucesfully: " ) + Globals::Get( ).Nickname + xorstr_( " - " ) + Globals::Get( ).NicknameHash , GREEN);
	return true;
}



bool FileChecking::CheckCurrentPath( ) {
	std::string CurrentPath = Mem::Get( ).GetProcessPath( Globals::Get( ).SelfID );

	if ( CurrentPath.empty( ) ) {
		Utils::Get( ).WarnMessage( _CHECKER , xorstr_( "failed to get path" ) , RED );
		return false;
	}

	try {
		std::vector<std::string> SearchStrings {
			xorstr_( ".i64" ),
			xorstr_( ".ida" )
		};
	
		if ( fs::exists( CurrentPath ) && fs::is_directory( CurrentPath ) ) {
			Utils::Get( ).WarnMessage( _CHECKER , xorstr_( "scanning " ) + CurrentPath , RED );

			//for ( const auto & entry : fs::directory_iterator( CurrentPath ) ) {
			//	try {
			//		std::string FileHash = Mem::Get( ).GetFileHash( entry.path( ).filename( ).string( ) );

			//		if ( FileHash.empty( ) ) {
			//			Utils::Get( ).WarnMessage( _CHECKER , xorstr_( "cant read memory of " ) + entry.path( ).filename( ).string( ) , RED );
			//			LogSystem::Get( ).Log( xorstr_( "[0] Can`t read " ) + entry.path( ).filename( ).string( ) );
			//			return false;
			//		}

			//		if ( FileHash == CLIENT_HASH ) {
			//			Globals::Get( ).CLIENT_NAME = entry.path( ).filename( ).string( );
			//		}

			//		if ( FileHash == DUMPER_HASH ) {
			//			Globals::Get( ).DUMPER_NAME = entry.path( ).filename( ).string( );
			//		}

			//		for ( const std::string & name : SearchStrings ) {
			//			if ( Utils::Get( ).CheckStrings( entry.path( ).filename( ).string( ) , name ) ) {
			//				Utils::Get( ).WarnMessage( _CHECKER , entry.path( ).filename( ).string( ) , YELLOW );
			//			}
			//		}
			//	}
			//	catch ( const std::filesystem::filesystem_error & ex ) {
			//		Utils::Get( ).WarnMessage( _CHECKER , xorstr_( "Error processing file: " ) + entry.path( ).filename( ).string( ) , RED );
			//		continue;  // Se ocorrer erro em um arquivo, continua para o próximo
			//	}
			//}

			//if ( Globals::Get( ).CLIENT_NAME.empty( ) ) {
			//	LogSystem::Get( ).Log( xorstr_( "[0] Can't find client" ) );
			//	return false;
			//}

			//if ( Globals::Get( ).DUMPER_NAME.empty( ) ){
			//	LogSystem::Get( ).Log( xorstr_( "[0] Can`t find socker" ) );
			//	return false;
			//}
		}
		else {
			Utils::Get( ).WarnMessage( _CHECKER , xorstr_( "invalid directory: " ) + CurrentPath , RED );
			LogSystem::Get( ).Log( xorstr_( "[02] Invalid directory") );
			return false;
		}
	}
	catch ( const std::filesystem::filesystem_error & ex ) {
		Utils::Get( ).WarnMessage( _CHECKER , xorstr_( "unexpected error" ) , RED );
		LogSystem::Get( ).Log( xorstr_( "[03] unexpected error" ) );
	}

	return true;
}



 



bool FileChecking::CheckHash( ) {






	return true;
}


bool FileChecking::ValidateFiles( ) {


	if ( !this->GetNickname( ) )
		return false;

	if ( !this->CheckCurrentPath( ) )
		return false;

	if ( !this->CheckHash( ) )
		return false;


	return true;
}