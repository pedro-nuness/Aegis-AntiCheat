#include "memory.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <TlHelp32.h>
#include <Psapi.h>
#include <tchar.h>
#include <fstream>

#include "..\Utils\singleton.h"
#include "..\Utils\utils.h"
#include "..\Utils\SHA1\sha1.h"



void Mem::WaitModule( int PID , std::string Module )
{
	std::cout << "Waiting for " << Module;
	std::cout << std::endl;

	while ( true )
	{
		if ( CheckModule( PID , Module ) )
		{
			Utils::Get( ).Warn( GREEN );
			std::cout << "Successfully found " << Module << "!\n\n";
			break;
		}

		std::this_thread::sleep_for( std::chrono::milliseconds( 500 ) ); // Sleep,
	}
}

bool Mem::CheckModule( int ID , std::string bModule )
{
	std::vector<std::string> Modules = GetModules( ID );//Get all loaded mudles

	for ( auto current_module : Modules )//Loop throw them
	{
		//std::cout << current_module << std::endl;

		if ( Utils::Get( ).CheckStrings( current_module , bModule ) )//Check them if we found some 
		{
			return true;
		}
	}
	return false;
}

DWORD Mem::GetProcessID( LPCTSTR ProcessName ) // non-conflicting function name
{
	PROCESSENTRY32 pt;
	HANDLE hsnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS , 0 );
	pt.dwSize = sizeof( PROCESSENTRY32 );
	if ( Process32First( hsnap , &pt ) ) { // must call this first
		do {
			if ( !lstrcmpi( pt.szExeFile , ProcessName ) ) {
				CloseHandle( hsnap );
				return pt.th32ProcessID;
			}
		} while ( Process32Next( hsnap , &pt ) );
	}
	CloseHandle( hsnap ); // close handle on failure
	return 0;
}


std::vector<std::string> Mem::GetModules( DWORD processID )
{
	std::vector<std::string> modules;

	HMODULE hMods[ 1024 ];
	HANDLE hProcess;
	DWORD cbNeeded;
	unsigned int i;

	// Print the process identifier.

	//printf("\nProcess ID: %u\n", processID);

	// Get a handle to the process.

	hProcess = OpenProcess( PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ ,
		FALSE , processID );
	if ( NULL == hProcess )
		return modules;

	// Get a list of all the modules in this process.

	if ( EnumProcessModules( hProcess , hMods , sizeof( hMods ) , &cbNeeded ) )
	{
		for ( i = 0; i < ( cbNeeded / sizeof( HMODULE ) ); i++ )
		{
			TCHAR szModName[ MAX_PATH ];

			// Get the full path to the module's file.

			if ( GetModuleBaseName( hProcess , hMods[ i ] , szModName ,
				sizeof( szModName ) / sizeof( TCHAR ) ) )
			{
				// Print the module name and handle value.
				//_tprintf(TEXT("\t%s (0x%08X)\n"), szModName, hMods[i]);
				modules.emplace_back( szModName );
			}
		}
	}

	// Release the handle to the process.

	CloseHandle( hProcess );

	return modules;
}

BOOL CALLBACK sEnumWindows( HWND hwnd , LPARAM lParam ) {
	const DWORD TITLE_SIZE = 1024;
	WCHAR windowTitle[ TITLE_SIZE ];

	GetWindowTextW( hwnd , windowTitle , TITLE_SIZE );

	int length = ::GetWindowTextLength( hwnd );
	std::string title = Mem::Get( ).ConvertWchar( &windowTitle[ 0 ] );
	if ( !IsWindowVisible( hwnd ) || length == 0 || title == "Program Manager" ) {
		return TRUE;
	}

	// Retrieve the pointer passed into this callback, and re-'type' it.
	// The only way for a C API to pass arbitrary data is by means of a void*.
	std::vector<std::string> & titles =
		*reinterpret_cast< std::vector<std::string>* >( lParam );
	titles.push_back( title );

	return TRUE;
}

std::vector<std::string> Mem::EnumAllWindows( ) {
	std::vector<std::string> titles;
	EnumWindows( sEnumWindows , reinterpret_cast< LPARAM >( &titles ) );

	return titles;
}

char Mem::asciitolower( char in ) {
	if ( in <= 'Z' && in >= 'A' )
		return in - ( 'Z' - 'z' );
	return in;
}


std::vector<std::string> Mem::EnumAllProcesses( ) {
	std::vector<std::string> Process;
	HANDLE hndl = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS | TH32CS_SNAPMODULE , 0 );
	if ( hndl )
	{
		PROCESSENTRY32  process = { sizeof( PROCESSENTRY32 ) };
		Process32First( hndl , &process );
		do
		{
			Process.emplace_back( process.szExeFile );
		} while ( Process32Next( hndl , &process ) );

		CloseHandle( hndl );
	}

	return Process;
}


bool Mem::ReadFileToMemory( const std::string & file_path , std::vector<uint8_t> * out_buffer )
{
	std::ifstream file_ifstream( file_path , std::ios::binary );

	if ( !file_ifstream )
		return false;

	out_buffer->assign( ( std::istreambuf_iterator<char>( file_ifstream ) ) , std::istreambuf_iterator<char>( ) );
	file_ifstream.close( );

	return true;
}

std::string  Mem::GetFileHash( std::string path )
{
	std::vector<uint8_t> CurrentBytes;
	if ( !ReadFileToMemory( path , &CurrentBytes ) )
	{
		Sleep( 1000 );
		exit( 0 );
	}

	SHA1 sha1;
	sha1.add( CurrentBytes.data( ) + 0 , CurrentBytes.size( ) );
	return sha1.getHash( );
}

std::string Mem::GenerateHash( std::string msg ) {
	SHA1 sha1;
	sha1.add( msg.data( ) , msg.size( ) );
	return sha1.getHash( );
}

std::string Mem::ConvertWchar( WCHAR inCharText[ 260 ] )
{
	//convert from wide char to narrow char array
	char ch[ 260 ];
	char DefChar = ' ';
	WideCharToMultiByte( CP_ACP , 0 , inCharText , -1 , ch , 260 , &DefChar , NULL );

	//A std:string  using the char* constructor.
	return std::string( ch );
}


uintptr_t Mem::GetModule( const std::string & ModuleName , int processID )
{
	uintptr_t wModule {};
	HMODULE hMods[ 1024 ];
	HANDLE hProcess;
	DWORD cbNeeded;
	unsigned int i;

	// Print the process identifier.

	//printf("\nProcess ID: %u\n", processID);

	// Get a handle to the process.

	hProcess = OpenProcess( PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ ,
		FALSE , processID );
	if ( NULL == hProcess )
		return wModule;

	// Get a list of all the modules in this process.

	if ( EnumProcessModules( hProcess , hMods , sizeof( hMods ) , &cbNeeded ) )
	{
		for ( i = 0; i < ( cbNeeded / sizeof( HMODULE ) ); i++ )
		{
			TCHAR szModName[ MAX_PATH ];

			// Get the full path to the module's file.

			if ( GetModuleFileNameEx( hProcess , hMods[ i ] , szModName ,
				sizeof( szModName ) / sizeof( TCHAR ) ) )
			{
				std::string cModule = szModName;

				size_t found = cModule.find( ModuleName );
				if ( found != std::string::npos )
				{
					wModule = ( uintptr_t ) hMods[ i ];
					//std::cout << "Found " << ModuleName << " at " << wModule << std::endl;

					break;
				}
			}
		}
	}

	// Release the handle to the process.

	CloseHandle( hProcess );

	return wModule;
}

bool Mem::SearchStringInDump( const std::vector<MemoryRegion> & memoryDump , const std::string & searchString ) {
	for ( const auto & region : memoryDump ) {
		if ( std::string( region.buffer.begin( ) , region.buffer.end( ) ).find( searchString ) != std::string::npos ) {
			//std::cout << "String encontrada no endereço: " << region.baseAddress << std::endl;
			return true;
		}
	}
	return false;
}

std::vector<std::pair<std::string , LPVOID>>  Mem::SearchStringsInDump( const std::vector<MemoryRegion> & memoryDump , std::vector< std::string> & searchStrings  ) {
	std::vector<std::pair<std::string , LPVOID>> data;
	for ( auto searchString : searchStrings ) {
		for ( const auto & region : memoryDump ) {
			if ( std::string( region.buffer.begin( ) , region.buffer.end( ) ).find( searchString ) != std::string::npos ) {
				data.push_back( std::make_pair( searchString , region.baseAddress ) );
				break;
			}
		}
	}
	return data;
}

// Callback function for EnumWindows
BOOL CALLBACK Mem::EnumWindowsProc( HWND hwnd , LPARAM lParam  ) {
	std::vector<WindowInfo> * Windows = reinterpret_cast< std::vector<WindowInfo> * >( lParam );
	DWORD processId;
	GetWindowThreadProcessId( hwnd , &processId );

	// Store window handle and process ID
	Windows->push_back( { hwnd, processId } );

	return TRUE;
}

uintptr_t Mem::GetModuleBaseAddress( std::string  lpszModuleName , DWORD PID ) {
	uintptr_t dwModuleBaseAddress = 0;
	HANDLE hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE , PID );
	MODULEENTRY32 ModuleEntry32 = { 0 };
	ModuleEntry32.dwSize = sizeof( MODULEENTRY32 );

	if ( Module32First( hSnapshot , &ModuleEntry32 ) )
	{
		do {
			if ( _tcscmp( ModuleEntry32.szModule , lpszModuleName.c_str( ) ) == 0 )
			{
				dwModuleBaseAddress = ( uintptr_t ) ModuleEntry32.modBaseAddr;
				//this->pSize = ModuleEntry32.modBaseSize;
				break;
			}
		} while ( Module32Next( hSnapshot , &ModuleEntry32 ) );


	}
	CloseHandle( hSnapshot );
	return dwModuleBaseAddress;
}

bool Mem::DumpProcessMemory( HANDLE hProcess , std::vector<MemoryRegion> & memoryDump ) {
	SYSTEM_INFO sysInfo;
	GetSystemInfo( &sysInfo );

	LPCVOID startAddress = sysInfo.lpMinimumApplicationAddress;
	LPCVOID endAddress = sysInfo.lpMaximumApplicationAddress;

	MEMORY_BASIC_INFORMATION mbi;
	while ( startAddress < endAddress ) {
		if ( VirtualQueryEx( hProcess , startAddress , &mbi , sizeof( mbi ) ) == 0 ) {
			break;
		}

		// Verificar se a região pode ser lida
		if ( mbi.State == MEM_COMMIT && ( ( mbi.Protect & PAGE_READONLY ) || ( mbi.Protect & PAGE_READWRITE ) ) ) {
			MemoryRegion region;
			region.baseAddress = mbi.BaseAddress;
			region.size = mbi.RegionSize;
			region.buffer.resize( mbi.RegionSize );

			SIZE_T bytesRead;
			if ( ReadProcessMemory( hProcess , mbi.BaseAddress , &region.buffer[ 0 ] , mbi.RegionSize , &bytesRead ) ) {
				memoryDump.push_back( region );
			}
		}

		startAddress = ( LPCVOID ) ( ( SIZE_T ) mbi.BaseAddress + mbi.RegionSize );
	}
	return true;
}

std::string Mem::GetProcessName( DWORD PID ) {
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof( processInfo );
	HANDLE processesSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS , NULL );
	if ( processesSnapshot == INVALID_HANDLE_VALUE )
	{
		return "";
	}

	for ( BOOL bok = Process32First( processesSnapshot , &processInfo ); bok; bok = Process32Next( processesSnapshot , &processInfo ) )
	{
		if ( PID == processInfo.th32ProcessID )
		{
			return processInfo.szExeFile;
		}

	}
	CloseHandle( processesSnapshot );
	return "";
}

HANDLE Mem::GetProcessHandle( DWORD PID )
{
	auto processHandle = OpenProcess( PROCESS_ALL_ACCESS , FALSE , PID );
	if ( processHandle == INVALID_HANDLE_VALUE || processHandle == NULL ) {
#ifdef _DEBUG
		std::cerr << "Failed to open process -- invalid handle" << std::endl;
		std::cerr << "Error code: " << GetLastError( ) << std::endl;
		throw "Failed to open process";
#endif
		return NULL;
	}

	return processHandle;
}

uintptr_t Mem::GetAddressFromSignature( DWORD PID , std::string module_name , std::vector<int> signature ) {

	HANDLE processHandle = GetProcessHandle( PID );

	if ( processHandle == NULL ) {
		return NULL;
	}

	auto module = GetModuleBaseAddress( module_name.c_str( ) , PID );
	auto module_size = GetModuleSize( module_name.c_str( ) , PID );

	if ( !module  ) {
		std::cout << "!module!\n";
		return NULL;
	}

	if ( !module_size ) {
		std::cout << "!size\n";
		return NULL;
	}

	std::vector<byte> memBuffer( module_size );

	int nearest = 0;

	if ( !ReadProcessMemory( processHandle , ( LPCVOID ) ( module ) , memBuffer.data( ) , module_size , NULL ) ) {
		//std::cout << GetLastError( ) << std::endl;
		CloseHandle( processHandle );
		return NULL;
	}
	for ( int i = 0; i < module_size; i++ ) {
		for ( uintptr_t j = 0; j < signature.size( ); j++ ) {
			if ( signature.at( j ) != -1 && signature[ j ] != memBuffer[ i + j ] )
			//	std::cout << std::hex << signature.at( j ) << " - " << ( void * ) memBuffer[ i + j ] << std::endl;
			break;
			//if ( signature[ j ] == memBuffer[ i + j ] && j > 0 )
				//std::cout << std::hex << int( signature[ j ] ) << std::hex << int( memBuffer[ i + j ] ) << j << std::endl;
			if ( j + 1 == signature.size( ) ) {
				CloseHandle( processHandle );
				return module + i;
			}
		}
	}
	CloseHandle( processHandle );
	return NULL;
}



bool Mem::IsPIDRunning( DWORD dwPid ) {
	HANDLE Process = Mem::Get( ).GetProcessHandle( dwPid );

	if ( Process != NULL ) {
		CloseHandle( Process );
		return true;
	}

	CloseHandle( Process );
	return false;
}

DWORD Mem::GetModuleSize( std::string lpszModuleName , DWORD PID ) {
	uintptr_t dwModuleBaseAddress = 0;
	HANDLE hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE , PID );
	MODULEENTRY32 ModuleEntry32 = { 0 };
	ModuleEntry32.dwSize = sizeof( MODULEENTRY32 );
	DWORD size = 0;
	if ( Module32First( hSnapshot , &ModuleEntry32 ) )
	{
		do {
			if ( _tcscmp( ModuleEntry32.szModule , lpszModuleName.c_str( ) ) == 0 )
			{
				size = ModuleEntry32.modBaseSize;
				break;
			}

		} while ( Module32Next( hSnapshot , &ModuleEntry32 ) );
	}
	CloseHandle( hSnapshot );
	return size;
}