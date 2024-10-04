#include "FileChecking.h"

#include "../Memory/memory.h"
#include "../Utils/utils.h"
#include "../Utils/xorstr.h"
#include "../../Globals/Globals.h"

#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;

bool FileChecking::isGameValid( std::string GameName ) {

	return true;
}

bool FileChecking::CheckCurrentPath( ) {
	std::string CurrentPath = Mem::Get( ).GetProcessPath( Globals::Get( ).SelfID );

	if ( CurrentPath.empty( ) ) {
		Utils::Get( ).WarnMessage( PURPLE , xorstr_( "checker" ) , xorstr_( "failed to get path" ) , RED );
		return false;
	}

	try {
		std::vector<std::string> SearchStrings {
			xorstr_( ".i64" ),
			xorstr_( ".ida" )
		};

		if ( fs::exists( CurrentPath ) && fs::is_directory( CurrentPath ) ) {
			Utils::Get( ).WarnMessage( PURPLE , xorstr_( "checker" ) , xorstr_( "scanning " ) + CurrentPath , RED );

			for ( const auto & entry : fs::directory_iterator( CurrentPath ) ) {
				for ( std::string name : SearchStrings ) {
					if ( Utils::Get( ).CheckStrings( entry.path( ).filename( ).string( ) , name ) ) {
						Utils::Get( ).WarnMessage( PURPLE , xorstr_( "checker" ) , entry.path( ).filename( ).string( ) , YELLOW );
					}
				}
			}
		}
		else {
			Utils::Get( ).WarnMessage( PURPLE , xorstr_( "checker" ) , xorstr_( "invalid directory: " ) + CurrentPath , RED );
		}
	}
	catch ( const std::filesystem::filesystem_error & ex ) {
		Utils::Get( ).WarnMessage( PURPLE , xorstr_( "checker" ) , xorstr_( "unexpected error" ) , RED );
	}

	return true;
}


bool FileChecking::ValidateFiles( ) {
	this->CheckCurrentPath( );

	return true;
}