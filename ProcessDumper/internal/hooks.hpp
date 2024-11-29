#include "../imports.h"
#include "../globals.h"

#include <cstdio>
#include <windows.h>
#include <tlhelp32.h>

#include <psapi.h>  // Para trabalhar com módulos de processos

#include "../client/client.h"
#include "../utils/Utils.h"
#include <filesystem>

#include <nlohmann/json.hpp>
using json = nlohmann::json;

#include <mutex>

std::mutex CallerMutex;

extern bool StopThreads;
static bool CallChecker = true;

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

void DeallocHooks( );

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



std::string AddressToString( void * address ) {
	std::stringstream ss;
	ss << std::uppercase << std::hex << reinterpret_cast< uintptr_t >( address );
	return ss.str( );
}


template <typename T>
std::string ValueToString( T parametro ) {
	std::stringstream ss;
	ss << std::uppercase << parametro;
	return ss.str( );
}


std::string ProtectionToString( DWORD protectFlags ) {
	switch ( protectFlags ) {
	case PAGE_NOACCESS: return xorstr_( "PAGE_NOACCESS" );
	case PAGE_READONLY: return xorstr_( "PAGE_READONLY" );
	case PAGE_READWRITE: return xorstr_( "PAGE_READWRITE" );
	case PAGE_WRITECOPY: return xorstr_( "PAGE_WRITECOPY" );
	case PAGE_EXECUTE: return xorstr_( "PAGE_EXECUTE" );
	case PAGE_EXECUTE_READ: return xorstr_( "PAGE_EXECUTE_READ" );
	case PAGE_EXECUTE_READWRITE: return xorstr_( "PAGE_EXECUTE_READWRITE" );
	case PAGE_EXECUTE_WRITECOPY: return xorstr_( "PAGE_EXECUTE_WRITECOPY" );
	case PAGE_GUARD: return xorstr_( "PAGE_GUARD" );
	case PAGE_NOCACHE: return xorstr_( "PAGE_NOCACHE" );
	case PAGE_WRITECOMBINE: return xorstr_( "PAGE_WRITECOMBINE" );
	default: return xorstr_( "Unknown Protection" );
	}
}

std::string GetModuleName( HMODULE hModule ) {
	char moduleName[ MAX_PATH ];
	if ( GetModuleFileNameExA( GetCurrentProcess( ) , hModule , moduleName , sizeof( moduleName ) ) ) {
		return std::string( moduleName );
	}
	return xorstr_( "Unknown Module" );
}

template <typename T>
T ReadValueAtAddress( void * address ) {
	// Lê os dados do endereço especificado e converte para o tipo T
	T value;
	memcpy( &value , address , sizeof( T ) );
	return value;
}

// Função para ler memória como uma string de chars
std::string ReadMemoryAsString( void * address , size_t length ) {
	std::string result;
	char * buffer = new char[ length + 1 ]; // +1 para o caractere de terminação nulo
	memcpy( buffer , address , length );
	buffer[ length ] = '\0'; // Garantir terminação nula
	result = std::string( buffer );
	delete[ ] buffer;
	return result;
}

std::string CheckMemoryRegion( void * address , SIZE_T SIZE ) {
	MEMORY_BASIC_INFORMATION mbi;
	SIZE_T result = VirtualQueryEx( GetCurrentProcess( ) , address , &mbi , sizeof( mbi ) );

	std::stringstream ss;

	if ( result == 0 ) {
		ss << xorstr_( "Error querying memory: " ) << GetLastError( ) << std::endl;
		return ss.str( );
	}

	std::string AllocationProtect = ProtectionToString( mbi.AllocationProtect );
	std::string Protect = ProtectionToString( mbi.Protect );

	

	// Construindo a string com as informações da região de memória
	ss << xorstr_( "Base address: " ) << mbi.BaseAddress << std::endl;
	ss << xorstr_( "Allocation base: " ) << mbi.AllocationBase << std::endl;
	ss << xorstr_( "Allocation protect: " ) << AllocationProtect << std::endl;
	ss << xorstr_( "Region size: " ) << mbi.RegionSize << xorstr_( " bytes" ) << std::endl;
	ss << xorstr_( "ReadSize: " ) << SIZE << xorstr_( " bytes" ) << std::endl;
	ss << xorstr_( "State: " ) << ( mbi.State == MEM_COMMIT ? xorstr_( "Committed" ) :
		mbi.State == MEM_RESERVE ? xorstr_( "Reserved" ) : xorstr_( "Free" ) ) << std::endl;
	ss << xorstr_( "Protection: " ) << Protect << std::endl;
	ss << xorstr_( "Type: " ) << ( mbi.Type == MEM_PRIVATE ? xorstr_( "Private" ) :
		mbi.Type == MEM_MAPPED ? xorstr_( "Mapped" ) : xorstr_( "Shared" ) ) << std::endl;

	// Verificando se o endereço está dentro da região
	if ( address >= mbi.BaseAddress && address < ( void * ) ( ( char * ) mbi.BaseAddress + mbi.RegionSize ) ) {
		ss << xorstr_( "Address " ) << address << xorstr_( " is within the region." ) << std::endl;
	}
	else {
		ss << xorstr_( "Address " ) << address << xorstr_( " is not within the region." ) << std::endl;
	}

	if ( ( Utils::Get( ).CheckStrings( AllocationProtect , xorstr_( "READ" ) ) ||
		Utils::Get( ).CheckStrings( Protect , xorstr_( "READ" ) ) ) ) {
		// Lendo o valor no endereço para diferentes tipos
		// Vamos tentar interpretar os bytes como diferentes tipos:
		int intValue = ReadValueAtAddress<int>( address );
		float floatValue = ReadValueAtAddress<float>( address );
		double doubleValue = ReadValueAtAddress<double>( address );

		ss << xorstr_( "Value at address (as int): " ) << intValue << std::endl;
		ss << xorstr_( "Value at address (as float): " ) << floatValue << std::endl;
		ss << xorstr_( "Value at address (as double): " ) << doubleValue << std::endl;
		ss << xorstr_( "Value at address (as string): " ) << ReadMemoryAsString( address , SIZE ) << std::endl;

	}

	char buffer[ MAX_PATH ];
	// Get the path of the executable
	HMODULE hModule = GetModuleHandle( NULL );
	GetModuleFileNameA( hModule , buffer , MAX_PATH );
	// Store the buffer in a string
	std::string exePath( buffer );

	ss << xorstr_( "ExePath: " ) << exePath << std::endl;

	return ss.str( );  // Retorna a string construída
}


void ThreadDetach( std::string Caller , void * Address , SIZE_T size ) {

	std::string Log = Caller + xorstr_( "\n " );

	if ( Address != nullptr ) {
		std::string Mem = CheckMemoryRegion( Address , size );
		if ( Mem.empty( ) )
			return;

		Log += Mem;
	}
	else
		Log += xorstr_( "nullptr" );

	if ( client::Get( ).SendMessageToServer( Log , BAN ) ) {
		StopThreads = true;
	}

}




bool CheckTarget( HANDLE hProcess , void * Address , SIZE_T size , std::string Caller ) {
	if ( !CallChecker )
		return true;

	DWORD DayzPID = GetPID( "DayZ_x64.exe" );
	if ( DayzPID ) {
		DWORD CurrentPID = GetProcessId( hProcess );
		if ( DayzPID == CurrentPID ) {
			std::lock_guard<std::mutex> lock( CallerMutex );
			std::thread( ThreadDetach , Caller , Address , size ).detach( );
			CallChecker = false;
		}
	}

	return true;
}

/* WriteProcessMemory */
typedef BOOL( WINAPI * tWriteProcessMemory )( HANDLE  hProcess , LPVOID  lpBaseAddress , LPCVOID lpBuffer , SIZE_T  nSize , SIZE_T * lpNumberOfBytesWritten );
tWriteProcessMemory pWriteProcessMemory = nullptr; // original function pointer after hook
bool WINAPI hookedWriteProcessMemory( HANDLE  hProcess , LPVOID  lpBaseAddress , LPCVOID lpBuffer , SIZE_T  nSize , SIZE_T * lpNumberOfBytesWritten ) {

	//if you managed to bypass the open handle protection, this will as well fuck you, if trying to write memory on user mode
	CheckTarget( hProcess , lpBaseAddress , nSize , xorstr_( "WriteProcessMemory" ) );


	return pWriteProcessMemory( hProcess , lpBaseAddress , lpBuffer , nSize , lpNumberOfBytesWritten );
}

typedef BOOL( WINAPI * SetWindowDisplayAffinity_t )( HWND , DWORD );
SetWindowDisplayAffinity_t OriginalSetWindowDisplayAffinity = nullptr;

// Hooked function
BOOL WINAPI hookedSetWindowDisplayAffinity( HWND hWnd , DWORD dwAffinity ) {
	// Block other affinities, you're cooked 100%, unless you changed the function name or sum shit
	if ( dwAffinity != WDA_NONE ) {
		return TRUE;
	}

	// Call the original function
	return OriginalSetWindowDisplayAffinity( hWnd , dwAffinity );
}

/* ReadProcessMemory */
typedef BOOL( WINAPI * tReadProcessMemory )( HANDLE  hProcess , LPCVOID lpBaseAddress , LPVOID  lpBuffer , SIZE_T  nSize , SIZE_T * lpNumberOfBytesRead );
tReadProcessMemory pReadProcessMemory = nullptr;
bool WINAPI hookedReadProcessMemory( HANDLE  hProcess , LPCVOID lpBaseAddress , LPVOID  lpBuffer , SIZE_T  nSize , SIZE_T * lpNumberOfBytesRead ) {

	CheckTarget( hProcess , const_cast< void * >( lpBaseAddress ) , nSize , xorstr_( "ReadProcessMemory" ) );

	return pReadProcessMemory( hProcess , lpBaseAddress , lpBuffer , nSize , lpNumberOfBytesRead );
}


typedef NTSTATUS( NTAPI * tNtRaiseHardError )( NTSTATUS ErrorStatus , ULONG NumberOfParameters , ULONG UnicodeStringParameterMask , PULONG_PTR Parameters , ULONG ResponseOption , PULONG Response );
tNtRaiseHardError pNtRaiseHardError;
NTSTATUS hookedNtRaiseHardError( NTSTATUS ErrorStatus , ULONG NumberOfParameters , ULONG UnicodeStringParameterMask , PULONG_PTR Parameters , ULONG ResponseOption , PULONG Response ) {
	return NULL;
}