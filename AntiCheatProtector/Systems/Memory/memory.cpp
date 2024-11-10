#include "memory.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <TlHelp32.h>
#include <Psapi.h>
#include <tchar.h>
#include <fstream>
#include <windows.h>
#include <winternl.h>
#include <vector>
#include <iostream>
#include <wintrust.h>
#include <Softpub.h>
#include <iostream>
#include <aclapi.h>
#include <sddl.h>

#include "..\Utils\singleton.h"
#include "..\Utils\utils.h"
#include "..\Utils\SHA1\sha1.h"
#include "..\Utils\xorstr.h"




#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004





#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "ntdll.lib")

typedef NTSTATUS( NTAPI * NtQuerySystemInformationPtr )(
	SYSTEM_INFORMATION_CLASS SystemInformationClass ,
	PVOID                    SystemInformation ,
	ULONG                    SystemInformationLength ,
	PULONG                   ReturnLength
	);


#ifndef SystemHandleInformation
#define SystemHandleInformation (SYSTEM_INFORMATION_CLASS)16
#endif

std::vector<SYSTEM_HANDLE> Mem::GetHandlesForProcess( DWORD processId )
{
	NtQuerySystemInformationPtr NtQuerySystemInformation = ( NtQuerySystemInformationPtr ) GetProcAddress(
		GetModuleHandle( "ntdll.dll" ) , "NtQuerySystemInformation" );

	if ( !NtQuerySystemInformation ) {
		std::cerr << "Não foi possível obter NtQuerySystemInformation." << std::endl;
		return {};
	}

	ULONG bufferSize = 0x10000;
	PSYSTEM_HANDLE_INFORMATION handleInfo = nullptr;
	NTSTATUS status;

	do {
		handleInfo = ( PSYSTEM_HANDLE_INFORMATION ) realloc( handleInfo , bufferSize );
		status = NtQuerySystemInformation( SystemHandleInformation , handleInfo , bufferSize , &bufferSize );
		if ( status == STATUS_INFO_LENGTH_MISMATCH ) {
			bufferSize *= 2;
		}
		else if ( !NT_SUCCESS( status ) ) {
			std::cerr << "NtQuerySystemInformation falhou com status: 0x" << std::hex << status << std::endl;
			free( handleInfo );
			return {};
		}
	} while ( status == STATUS_INFO_LENGTH_MISMATCH );

	std::vector< SYSTEM_HANDLE > Handles;

	ULONG oldPid = NULL;
	DWORD currentPID = GetCurrentProcessId( );
	for ( ULONG i = 0; i < handleInfo->HandleCount; i++ ) {
		SYSTEM_HANDLE handle = handleInfo->Handles[ i ];
		if ( handle.ProcessId != currentPID ) {
			if ( oldPid != handle.ProcessId )
			{
				Handles.emplace_back( handle );
				oldPid = handle.ProcessId;
			}
		}
	}

	free( handleInfo );

	return Handles;
}

bool Mem::RestrictProcessAccess( ) {
	HANDLE hProcess = GetCurrentProcess( );
	PSECURITY_DESCRIPTOR pSD = NULL;
	PACL pOldDACL = NULL , pNewDACL = NULL;
	EXPLICIT_ACCESS ea = { 0 };
	PSID pEveryoneSID = NULL;
	SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;


	if ( GetSecurityInfo( hProcess , SE_KERNEL_OBJECT , DACL_SECURITY_INFORMATION ,
		NULL , NULL , &pOldDACL , NULL , &pSD ) != ERROR_SUCCESS ) {
		return false;
	}


	if ( !AllocateAndInitializeSid( &SIDAuthWorld , 1 ,
		SECURITY_WORLD_RID ,
		0 , 0 , 0 , 0 , 0 , 0 , 0 ,
		&pEveryoneSID ) ) {
		if ( pSD ) LocalFree( pSD );
		return false;
	}

	ea.grfAccessPermissions = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE  | PROCESS_VM_READ;
	ea.grfAccessMode = DENY_ACCESS;
	ea.grfInheritance = NO_INHERITANCE;
	ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	ea.Trustee.ptstrName = ( LPSTR ) pEveryoneSID;

	if ( SetEntriesInAcl( 1 , &ea , pOldDACL , &pNewDACL ) != ERROR_SUCCESS ) {
		if ( pSD ) LocalFree( pSD );
		if ( pEveryoneSID ) FreeSid( pEveryoneSID );
		return false;
	}

	if ( SetSecurityInfo( hProcess , SE_KERNEL_OBJECT , DACL_SECURITY_INFORMATION ,
		NULL , NULL , pNewDACL , NULL ) != ERROR_SUCCESS ) {
		if ( pSD ) LocalFree( pSD );
		if ( pEveryoneSID ) FreeSid( pEveryoneSID );
		if ( pNewDACL ) LocalFree( pNewDACL );
		return false;
	}

	if ( pSD ) LocalFree( pSD );
	if ( pEveryoneSID ) FreeSid( pEveryoneSID );
	if ( pNewDACL ) LocalFree( pNewDACL );

	return true;
}

float Mem::GetProcessMemoryUsage( DWORD processID ) {
	HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ , FALSE , processID );

	if ( hProcess == NULL ) {
		return 0.0f;
	}

	PROCESS_MEMORY_COUNTERS pmc;
	if ( GetProcessMemoryInfo( hProcess , &pmc , sizeof( pmc ) ) ) {
		float memoryUsageMB = static_cast< float >( pmc.WorkingSetSize ) / ( 1024 * 1024 );
		CloseHandle( hProcess );
		return memoryUsageMB;
	}

	CloseHandle( hProcess );
	return 0.0f;
}


std::string Mem::GetProcessExecutablePath( DWORD processID ) {
	std::string processPath;
	HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ , FALSE , processID );

	if ( hProcess != NULL ) {
		char exePath[ MAX_PATH ];
		if ( GetModuleFileNameEx( hProcess , NULL , exePath , MAX_PATH ) ) {
			processPath = exePath;
		}
		CloseHandle( hProcess );
	}

	return processPath;

}

bool Mem::VerifyFileSignature( const std::string & filePath ) {
	WINTRUST_FILE_INFO fileInfo = {};
	fileInfo.cbStruct = sizeof( WINTRUST_FILE_INFO );
	fileInfo.pcwszFilePath = std::wstring( filePath.begin( ) , filePath.end( ) ).c_str( );
	fileInfo.hFile = nullptr;
	fileInfo.pgKnownSubject = nullptr;

	WINTRUST_DATA trustData = {};
	trustData.cbStruct = sizeof( WINTRUST_DATA );
	trustData.dwUIChoice = WTD_UI_NONE;
	trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
	trustData.dwUnionChoice = WTD_CHOICE_FILE;
	trustData.pFile = &fileInfo;
	trustData.dwStateAction = WTD_STATEACTION_VERIFY;
	trustData.dwProvFlags = WTD_SAFER_FLAG;
	trustData.hWVTStateData = nullptr;

	GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

	LONG status = WinVerifyTrust( nullptr , &policyGUID , &trustData );

	trustData.dwStateAction = WTD_STATEACTION_CLOSE;
	WinVerifyTrust( nullptr , &policyGUID , &trustData );

	if ( status == ERROR_SUCCESS ) {
		return true;
	}
	else {
		return false;
	}
}


bool Mem::ProcessIsOnSystemFolder( int pid ) {
	std::string Path = GetProcessExecutablePath( pid );

	return Utils::Get( ).CheckStrings( Path , xorstr_( "\\System32\\" ) ) ||
		Utils::Get( ).CheckStrings( Path , xorstr_( "\\SysWOW64\\" ) ) ||
		Utils::Get( ).CheckStrings( Path , xorstr_( "\\SystemApps\\" ) ) ||
		Utils::Get( ).CheckStrings( Path , xorstr_( "\\WindowsApps\\" ) );
}

bool Mem::VerifySignature( HANDLE hProcess ) {
	char processImagePath[ MAX_PATH ];
	if ( GetModuleFileNameExA( hProcess , nullptr , processImagePath , MAX_PATH ) == 0 )
	{
		std::cerr << "Could not get process image path." << std::endl;
		CloseHandle( hProcess );
		return false;
	}

	wchar_t wideProcessImagePath[ MAX_PATH ];
	// Converte de multibyte (char) para wide char (wchar_t)
	MultiByteToWideChar( CP_ACP , 0 , processImagePath , -1 , wideProcessImagePath , MAX_PATH );
	

	// Initialize the WINTRUST_FILE_INFO structure
	WINTRUST_FILE_INFO fileInfo;
	memset( &fileInfo , 0 , sizeof( fileInfo ) );
	fileInfo.cbStruct = sizeof( WINTRUST_FILE_INFO );
	fileInfo.pcwszFilePath = wideProcessImagePath;

	// Initialize the WINTRUST_DATA structure
	WINTRUST_DATA trustData;
	memset( &trustData , 0 , sizeof( trustData ) );
	trustData.cbStruct = sizeof( WINTRUST_DATA );
	trustData.dwUIChoice = WTD_UI_NONE;
	trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
	trustData.dwUnionChoice = WTD_CHOICE_FILE;
	trustData.pFile = &fileInfo;
	trustData.dwStateAction = WTD_STATEACTION_VERIFY;
	trustData.dwProvFlags = WTD_SAFER_FLAG;  // Trust verification flag

	// Use WinVerifyTrust to check if the file is signed and trusted
	GUID actionGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	LONG status = WinVerifyTrust( nullptr , &actionGUID , &trustData );

	// Clean up the state data
	trustData.dwStateAction = WTD_STATEACTION_CLOSE;
	WinVerifyTrust( nullptr , &actionGUID , &trustData );

	return status == ERROR_SUCCESS;
}

void Mem::WaitModule( int PID , std::string Module )
{
	//std::cout << "Waiting for " << Module;
	//std::cout << std::endl;

	while ( true )
	{
		if ( CheckModule( PID , Module ) )
		{
			Utils::Get( ).Warn( GREEN );
			//std::cout << "Successfully found " << Module << "!\n\n";
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

std::vector<std::pair<std::string , LPVOID>>  Mem::SearchStringsInDump( const std::vector<MemoryRegion> & memoryDump , std::vector< std::string> & searchStrings ) {
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
BOOL CALLBACK Mem::EnumWindowsProc( HWND hwnd , LPARAM lParam ) {
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

bool Mem::IsSystemProcess( HANDLE hProcess ) {
	HANDLE hToken;
	if ( !OpenProcessToken( hProcess , TOKEN_QUERY , &hToken ) )
	{
		std::cerr << "Could not open process token." << std::endl;
		CloseHandle( hProcess );
		return false;
	}

	// Get the user information from the token
	DWORD tokenInfoLength = 0;
	GetTokenInformation( hToken , TokenUser , nullptr , 0 , &tokenInfoLength );

	PTOKEN_USER tokenUser = ( PTOKEN_USER ) malloc( tokenInfoLength );
	if ( GetTokenInformation( hToken , TokenUser , tokenUser , tokenInfoLength , &tokenInfoLength ) )
	{
		LPSTR sidString = nullptr;
		ConvertSidToStringSidA( tokenUser->User.Sid , &sidString );

		// SYSTEM's SID is S-1-5-18
		if ( sidString && strcmp( sidString , "S-1-5-18" ) == 0 )
		{
			LocalFree( sidString );
			free( tokenUser );
			CloseHandle( hToken );
			CloseHandle( hProcess );
			return true;  // Process is running as SYSTEM
		}

		LocalFree( sidString );
	}

	free( tokenUser );
	CloseHandle( hToken );
	CloseHandle( hProcess );

	return false;
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

	if ( !module ) {
		//std::cout << "!module!\n";
		return NULL;
	}

	if ( !module_size ) {
		//std::cout << "!size\n";
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
				//	//std::cout << std::hex << signature.at( j ) << " - " << ( void * ) memBuffer[ i + j ] << std::endl;
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