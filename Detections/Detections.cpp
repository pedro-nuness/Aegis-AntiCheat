#include "Detections.h"
#include <iostream>
#include <thread>
#include <Windows.h>
#include <unordered_map>

#include "../Memory/memory.h"
#include "../Utils/crypt_str.h"

#include "../Monitoring/Monitoring.h"



void Detections::Init( ) {
	std::thread( &Detections::InitialThread , this ).detach();
}

std::string Detections::GenerateDetectionStatus( DWORD PID ) {
	std::string str = crypt_str( "[DETECTION]\n Found Infected Process\n" );
	str += Mem::Get( ).GetProcessName( PID ) + crypt_str("\n");
	auto modules = Mem::Get( ).GetModules( PID );
	return str;
}

DETECTION_STATUS Detections::ScanWindows( ) {
	std::cout << crypt_str("[DETECTION THREAD] Starting Window scan!\n");
	std::unordered_map<DWORD , int> Map;

	// Enumerate all top-level windows
	std::vector<WindowInfo> Windows;
	EnumWindows( Mem::EnumWindowsProc , ( LPARAM ) ( &Windows ) );

	for ( const auto & window : Windows ) {
		if ( window.processId == this->MomProcess || window.processId == this->ProtectProcess ) {
			continue;
		}

		// Check for overlay characteristics
		LONG_PTR exStyle = GetWindowLongPtr( window.hwnd , GWL_EXSTYLE );
		if ( exStyle & WS_EX_LAYERED | WS_EX_TRANSPARENT ) {
			if ( Map[ window.processId ] ) {
				continue;
			}

			Map[ window.processId ]++;
		}
	}

	for ( const auto & pair : Map ) {

		std::cout << "[SCAN]: " << Mem::Get( ).GetProcessName( pair.first ) << "\n";

		HANDLE hProcess = OpenProcess( PROCESS_VM_READ | PROCESS_QUERY_INFORMATION , FALSE , pair.first );

		if ( hProcess == NULL ) {
			continue;
		}

		std::vector<MemoryRegion> memoryDump;

		if ( Mem::Get( ).DumpProcessMemory( hProcess , memoryDump ) ) {
			std::vector<std::string> TargetStrings {
				crypt_str( "Aimbot" ),
				crypt_str( "Box" ),
				crypt_str( "Skeleton" ),
				crypt_str( "Distance" ),
				crypt_str( "ESP" ),
				crypt_str( "Hack" ),
				crypt_str( "Entities" ),
				crypt_str( "dayzinfected" ),
				crypt_str( "clothing" ),
				crypt_str( "dayzplayer" ),
				crypt_str( "dayzanimal" ),
				crypt_str( "inventoryItem" ),
				crypt_str( "ProxyMagazines" ),
				crypt_str( "Weapon" ),
				crypt_str( "DayZ_x64.exe" )
			};

			float Founds = 0;

			Mem::Get( ).SearchStringsInDump( memoryDump , TargetStrings , Founds );

			if ( Founds / ( float ) TargetStrings.size( ) > 0.7 ) {
				std::cout << crypt_str("[DETECTION] Found Infected Process: ") << Mem::Get( ).GetProcessName( pair.first ) << "\n";
				Monitoring::Get( ).SendDetectionInfo( GenerateDetectionStatus(pair.first) );
			}
			std::this_thread::sleep_for( std::chrono::milliseconds( 250 ) );
		}
	}
	std::cout << crypt_str("[DETECTION THREAD] Ending Window scan!\n");

	return NOTHING_DETECTED;
}

void Detections::InitialThread( ) {
	while ( true ) {
		
		this->ScanWindows( );


		std::cout << crypt_str("[DETECTION THREAD] Waiting...\n");
		std::this_thread::sleep_for( std::chrono::seconds( 120 ) );
	}
}