#include "imports.h"
#include "globals.h"
#include "utils/security.h"

#include "internal/hooks.hpp"
HINSTANCE DllHandle;

#define WIN32_LEAN_AND_MEAN

bool StopThreads = false;
bool InitializedHooks = false;


#include <fstream>
#include <filesystem>

namespace fs = std::filesystem;


void DeallocHooks( ) {
	MH_DisableHook( MH_ALL_HOOKS );
	MH_Uninitialize( );
	StopThreads = true;
}

BOOL EnumWindowsCallback( HWND hwnd , LPARAM lParam ) {
	DWORD windowProcessID;
	GetWindowThreadProcessId( hwnd , &windowProcessID );
	if ( windowProcessID == GetCurrentProcessId( ) ) {
		auto * windows = reinterpret_cast< std::vector<HWND>* >( lParam );
		windows->push_back( hwnd );
	}
	return TRUE;
}

std::vector<HWND> GetProcessWindows( DWORD processID ) {
	std::vector<HWND> windows;
	EnumWindows( EnumWindowsCallback , reinterpret_cast< LPARAM >( &windows ) );
	return windows;
}


void * LoadInternalResource( DWORD * buffer , int resourceID , LPSTR type ) {
	if ( DllHandle == NULL ) {
		//LogSystem::Get( ).ConsoleLog( _MAIN , std::to_string( resourceID ) + xorstr_( ": Error gettind dll module" ) , RED );
		return nullptr;
	}

	HRSRC hResInfo = FindResourceA( DllHandle , MAKEINTRESOURCE( resourceID ) , type );
	if ( hResInfo == NULL ) {
		//LogSystem::Get( ).ConsoleLog( _MAIN , std::to_string( resourceID ) + xorstr_( ": Error locating resources" ) , RED );
		return nullptr;
	}

	DWORD resourceSize = SizeofResource( DllHandle , hResInfo );
	if ( resourceSize == 0 ) {
		//LogSystem::Get( ).ConsoleLog( _MAIN , std::to_string( resourceID ) + xorstr_( ": Error gettind resource size" ) , RED );
		return nullptr;
	}

	HGLOBAL hResData = LoadResource( DllHandle , hResInfo );
	if ( hResData == NULL ) {
		//LogSystem::Get( ).ConsoleLog( _MAIN , std::to_string( resourceID ) + xorstr_( ": Error loading resource" ) , RED );
		return nullptr;
	}

	void * pResData = LockResource( hResData );
	if ( pResData == NULL ) {
		//LogSystem::Get( ).ConsoleLog( _MAIN , std::to_string( resourceID ) + xorstr_( ": Error locking resource" ) , RED );
		return nullptr;
	}

	*buffer = resourceSize;

	return pResData;
}

bool LoadLibraryWithMemory( char * data , DWORD size , std::string name = "" ) {
	std::string filename = ( name.empty( ) ? Utils::Get( ).GetRandomWord( 32 ) + xorstr_( ".dll" ) : name );

	// Pega caminho da pasta TEMP
	char tempPath[ MAX_PATH ];
	if ( !GetTempPathA( MAX_PATH , tempPath ) ) {

		//printf( "cant get temp\n" );
		return false;
	}


	std::string fullPath = std::string( tempPath ) + filename;



	// Salvar a DLL extraída em um arquivo temporário
	std::ofstream outFile( fullPath , std::ios::binary );
	if ( outFile || std::filesystem::exists( fullPath.c_str( ) ) ) {
		outFile.write( data , size );
		outFile.close( );

		// Carregar a DLL usando LoadLibrary
		HMODULE hModule = LoadLibrary( fullPath.c_str( ) );

		std::remove( fullPath.c_str( ) );

		if ( hModule ) {
			return true;
		}
		//printf( "hmodule is null\n" );
	}
	else {
		//printf( "cant create file\n" );
		//LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "Couldnt save library" ) , RED );
		return false;
	}

	return false;
}


#define LibCryptoID 103
#define LibSSLID 104

bool LoadAntiCheatResources( ) {
	{
		DWORD libCryptoSize = 0;
		void * libCrypto = LoadInternalResource( &libCryptoSize , LibCryptoID , RT_RCDATA );
		if ( libCrypto == nullptr ) {
			return false;
		}

		if ( !LoadLibraryWithMemory( ( char * ) libCrypto , libCryptoSize , xorstr_( "libcrypto-1_1-x64.dll" ) ) ) {
			//printf( "cant load libcrypto!\n" );
			return false;
		}
	}
	Sleep( 1500 );
	{
		DWORD libSSLSize = 0;
		void * libSSL = LoadInternalResource( &libSSLSize , LibSSLID , RT_RCDATA );
		if ( libSSL == nullptr ) {
			return false;
		}

		if ( !LoadLibraryWithMemory( ( char * ) libSSL , libSSLSize , xorstr_( "libssl-1_1-x64.dll" ) ) ) {
			//printf( "cant load libssl!\n" );
			return false;
		}
	}

	// LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "Resources loaded succesfully" ) , GREEN );

	return true;
}

DWORD WINAPI InitExec( PVOID base ) {
	//printf( "loaded1!\n" );

	if ( !LoadAntiCheatResources( ) ) {
		//printf( "cant load libs!\n" );
		return 0;
	}

	//printf( "loaded!\n" );

	::ShowWindow( ::GetConsoleWindow( ) , SW_SHOW );


	if ( MH_Initialize( ) != MH_OK ) {
		return 0;
	}

	if ( MH_CreateHookApi( L"kernel32.dll" , xorstr_( "GetThreadContext" ) , &hookedGetThreadContext , reinterpret_cast< void ** >( &pGetThreadContext ) ) != MH_OK ) {

	}
	else {

	}

	if ( MH_CreateHookApi( L"ntdll.dll" , xorstr_( "NtRaiseHardError" ) , &hookedNtRaiseHardError , reinterpret_cast< void ** >( &pNtRaiseHardError ) ) != MH_OK ) {

	}
	else {
	}

	/* RPM / WPM Hooks */
	if ( MH_CreateHookApi( L"kernel32.dll" , xorstr_( "WriteProcessMemory" ) , &hookedWriteProcessMemory , reinterpret_cast< void ** >( &pWriteProcessMemory ) ) != MH_OK ) {

	}
	else {

	}

	/* RPM / SWDP Hooks */
	if ( MH_CreateHookApi( L"user32.dll" , xorstr_( "SetWindowDisplayAffinity" ) , &hookedSetWindowDisplayAffinity , reinterpret_cast< void ** >( &OriginalSetWindowDisplayAffinity ) ) != MH_OK ) {
	}
	else {

	}

	if ( MH_CreateHookApi( L"kernel32.dll" , xorstr_( "ReadProcessMemory" ) , &hookedReadProcessMemory , reinterpret_cast< void ** >( &pReadProcessMemory ) ) != MH_OK ) {
	}
	else {
	}

	MH_EnableHook( MH_ALL_HOOKS );

	auto windows = GetProcessWindows( GetCurrentProcessId( ) );
	for ( auto window : windows ) {
		SetWindowDisplayAffinity( window , WDA_NONE );
	}

	while ( true ) {
		std::this_thread::sleep_for( std::chrono::seconds( 1 ) );
		if ( StopThreads ) {
			std::this_thread::sleep_for( std::chrono::seconds( 15 ) );
			DeallocHooks( );
			break;
		}
	}

	return 1;
}




int __stdcall DllMain( const HMODULE hModule , const std::uintptr_t reason , const void * reserved ) {
	if ( reason == 1 ) {
		/* Alocate Console */
		if ( globals::AllocateConsole == true ) {
			AllocConsole( );
			FILE * fp;
			freopen_s( &fp , "CONOUT$" , "w" , stdout );
		}

		DisableThreadLibraryCalls( hModule );

		DllHandle = hModule;

		CreateThread( nullptr , 0 , InitExec , hModule , 0 , nullptr );

		//hyde::CreateThread( InitExec , DllHandle );
		/*hyde::CreateThread( InitExec , DllHandle ); */
		//std::cout xorstr_("[-] Started Main Thread...\n");

		return true;
	}
	return true;
}

