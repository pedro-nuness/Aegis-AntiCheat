#include "../imports.h"
#include "../globals.h"

#include <cstdio>
#include <windows.h>
#include <tlhelp32.h>

#include "../client/sender.h"

#include <filesystem>

#include <nlohmann/json.hpp>
using json = nlohmann::json;

#include "../hardware/hardware.h"



typedef BOOL( WINAPI * tGetThreadContext )( HANDLE hThread , LPCONTEXT lpContext );
tGetThreadContext pGetThreadContext = nullptr;
bool WINAPI hookedGetThreadContext( HANDLE hThread , LPCONTEXT lpContext ) {
	BOOL result = ( *pGetThreadContext )( hThread , lpContext );
	if ( lpContext ) {
		lpContext->ContextFlags &= ~0x7F;
		lpContext->Dr0 = 0;
		lpContext->Dr1 = 0;
		lpContext->Dr2 = 0;
		lpContext->Dr3 = 0;
		lpContext->Dr6 = 0;
		lpContext->Dr7 = 0;
	}
	return pGetThreadContext( hThread , lpContext );
}



DWORD GetPID( LPCSTR ProcessName ) {
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
	return ( DWORD ) 0;
}



#include <mutex>

std::mutex CallerMutex;

bool CallChecker = true;

bool CheckTarget( HANDLE hProcess , std::string Caller ) {
	DWORD DayzPID = GetPID( "DayZ_x64.exe" );
	if ( DayzPID ) {
		DWORD CurrentPID = GetProcessId( hProcess );
		if ( DayzPID == CurrentPID ) {
			std::lock_guard<std::mutex> lock( CallerMutex );

			char buffer[ MAX_PATH ];
			// Get the path of the executable
			HMODULE hModule = GetModuleHandle( NULL );
			GetModuleFileNameA( hModule , buffer , MAX_PATH );
			// Store the buffer in a string
			std::string exePath( buffer );

			std::string IP = hardware::Get( ).GetIp( 54930 );
			if ( !IP.empty( ) ) {
				sender NewMessage( IP );
				json JS;

				//1 = BAN
				JS[ xorstr_( "request_type" ) ] = 1;
				JS[ xorstr_( "message" ) ] = Caller + xorstr_( " to Game!\n" ) + exePath;

				if ( NewMessage.SendMessageToServer( JS.dump( ) ) ) {
					exit( 0 );
				}
			}
		}
	}

	return true;
}


/* WriteProcessMemory */
typedef BOOL( WINAPI * tWriteProcessMemory )( HANDLE  hProcess , LPVOID  lpBaseAddress , LPCVOID lpBuffer , SIZE_T  nSize , SIZE_T * lpNumberOfBytesWritten );
tWriteProcessMemory pWriteProcessMemory = nullptr; // original function pointer after hook
bool WINAPI hookedWriteProcessMemory( HANDLE  hProcess , LPVOID  lpBaseAddress , LPCVOID lpBuffer , SIZE_T  nSize , SIZE_T * lpNumberOfBytesWritten ) {

	if ( CallChecker )
		CheckTarget( hProcess , xorstr_( "WriteProcessMemory" ) );

	//std::cout xorstr_( " [WriteProcessMemory-Dumped] called to id:" ) << GetProcessId(hProcess) << std::endl;


	return pWriteProcessMemory( hProcess , lpBaseAddress , lpBuffer , nSize , lpNumberOfBytesWritten );
}




/* ReadProcessMemory */
typedef BOOL( WINAPI * tReadProcessMemory )( HANDLE  hProcess , LPCVOID lpBaseAddress , LPVOID  lpBuffer , SIZE_T  nSize , SIZE_T * lpNumberOfBytesRead );
tReadProcessMemory pReadProcessMemory = nullptr;
bool WINAPI hookedReadProcessMemory( HANDLE  hProcess , LPCVOID lpBaseAddress , LPVOID  lpBuffer , SIZE_T  nSize , SIZE_T * lpNumberOfBytesRead ) {

	CheckTarget( hProcess , xorstr_( "ReadProcessMemory" ) );

	return pReadProcessMemory( hProcess , lpBaseAddress , lpBuffer , nSize , lpNumberOfBytesRead );
}

typedef BOOL( WINAPI * tDeleteFileW )( LPCWSTR lpFileName );
tDeleteFileW pDeleteFileW;
bool WINAPI hookedDeleteFileW( LPCWSTR lpFileName ) {

	return pDeleteFileW( lpFileName );
}

typedef BOOL( WINAPI * tDeleteFileA )( LPCSTR lpFileName );
tDeleteFileA pDeleteFileA;
bool WINAPI hookedDeleteFileA( LPCSTR lpFileName ) {

	return pDeleteFileA( lpFileName );
}

typedef NTSTATUS( NTAPI * tNtRaiseHardError )( NTSTATUS ErrorStatus , ULONG NumberOfParameters , ULONG UnicodeStringParameterMask , PULONG_PTR Parameters , ULONG ResponseOption , PULONG Response );
tNtRaiseHardError pNtRaiseHardError;
NTSTATUS hookedNtRaiseHardError( NTSTATUS ErrorStatus , ULONG NumberOfParameters , ULONG UnicodeStringParameterMask , PULONG_PTR Parameters , ULONG ResponseOption , PULONG Response ) {
	return NULL;
}