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
#include <unordered_map>


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


std::vector<ThreadInfo> Mem::Thread::EnumerateThreads( DWORD processID ) {
	std::vector<ThreadInfo> threadsInfo;

	HANDLE hThreadSnap = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD , 0 );
	if ( hThreadSnap == INVALID_HANDLE_VALUE ) {
		std::cerr << "Error: Unable to create snapshot of threads." << std::endl;
		return threadsInfo;
	}

	THREADENTRY32 te32;
	te32.dwSize = sizeof( THREADENTRY32 );

	if ( !Thread32First( hThreadSnap , &te32 ) ) {
		std::cerr << "Error: Unable to get first thread." << std::endl;
		CloseHandle( hThreadSnap );
		return threadsInfo;
	}

	do {
		if ( te32.th32OwnerProcessID == processID ) {
			ThreadInfo tInfo;
			tInfo.threadID = te32.th32ThreadID;
			tInfo.ownerProcessID = te32.th32OwnerProcessID;
			tInfo.priority = te32.tpBasePri;

			HANDLE hThread = OpenThread( THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT , FALSE , te32.th32ThreadID );
			if ( hThread ) {
				tInfo.threadHandle = hThread;

				CONTEXT context;
				context.ContextFlags = CONTEXT_FULL;  // Obtenha todos os registros da CPU
				if ( GetThreadContext( hThread , &context ) ) {
					// Para x86 (32-bit), use Esp
#if defined(_M_X64) || defined(_AMD64)
	// Para x64 (64-bit), use Rsp
					tInfo.stackAddress = ( LPVOID ) context.Rsp;
					// std::cout << "Stack Pointer (Rsp): " << ( LPVOID ) context.Rsp << std::endl;
#else
	// Para x86 (32-bit), use Esp
					tInfo.stackAddress = ( LPVOID ) context.Esp;
					//std::cout << "Stack Pointer (Esp): " << context.Esp << std::endl;
#endif
				}
				else {
					std::cerr << "Erro ao obter o contexto da thread." << std::endl;
				}


				// Obtenha tempos de criação, saída, kernel e usuário
				GetThreadTimes( hThread , &tInfo.creationTime , &tInfo.exitTime , &tInfo.kernelTime , &tInfo.userTime );

				CloseHandle( hThread );
			}

			threadsInfo.push_back( tInfo );
		}
	} while ( Thread32Next( hThreadSnap , &te32 ) );

	CloseHandle( hThreadSnap );
	return threadsInfo;
}

std::vector<ModuleInfo> Mem::Module::EnumerateModules( DWORD processID ) {
	std::vector<ModuleInfo> modulesInfo;

	HANDLE hModuleSnap = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE , processID );
	if ( hModuleSnap == INVALID_HANDLE_VALUE ) {
		std::cerr << "Error: Unable to create snapshot of modules for process ID " << processID << "." << std::endl;
		return modulesInfo;
	}

	MODULEENTRY32 me32;
	me32.dwSize = sizeof( MODULEENTRY32 );

	if ( !Module32First( hModuleSnap , &me32 ) ) {
		std::cerr << "Error: Unable to get first module." << std::endl;
		CloseHandle( hModuleSnap );
		return modulesInfo;
	}

	do {
		ModuleInfo mInfo;
		mInfo.moduleName = me32.szModule;
		mInfo.modulePath = me32.szExePath;
		mInfo.baseAddress = ( DWORD ) me32.modBaseAddr;
		mInfo.size = me32.modBaseSize;
		mInfo.moduleHandle = me32.hModule;

		modulesInfo.push_back( mInfo );
	} while ( Module32Next( hModuleSnap , &me32 ) );

	CloseHandle( hModuleSnap );
	return modulesInfo;
}


std::vector<SYSTEM_HANDLE> Mem::Handle::EnumerateHandles( DWORD processID ) {
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


bool Mem::Handle::CheckDangerousPermissions( HANDLE handle,DWORD * buffer ) {
	typedef NTSTATUS( WINAPI * NtQueryObjectFunc )(
		HANDLE ,
		OBJECT_INFORMATION_CLASS ,
		PVOID ,
		ULONG ,
		PULONG
		);

	HMODULE ntdll = GetModuleHandle( "ntdll.dll" );
	if ( !ntdll ) {
		std::cerr << "Falha ao carregar ntdll.dll." << std::endl;
		return false;
	}

	auto NtQueryObject = ( NtQueryObjectFunc ) GetProcAddress( ntdll , "NtQueryObject" );
	if ( !NtQueryObject ) {
		std::cerr << "Falha ao obter o endereço de NtQueryObject." << std::endl;
		return false;
	}

	struct OBJECT_BASIC_INFORMATION {
		ULONG Attributes;
		ACCESS_MASK GrantedAccess;
		ULONG HandleCount;
		ULONG PointerCount;
		ULONG Reserved[ 10 ];
	};

	OBJECT_BASIC_INFORMATION objectInfo;
	ULONG returnLength = 0;

	NTSTATUS status = NtQueryObject(
		handle ,
		ObjectBasicInformation ,
		&objectInfo ,
		sizeof( objectInfo ) ,
		&returnLength
	);

	if ( status != 0 ) {
		std::cerr << "NtQueryObject falhou. Status: 0x" << std::hex << status << std::endl;
		return false;
	}

	DWORD dangerousFlags = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD |
		PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | PROCESS_ALL_ACCESS;

	if ( buffer != nullptr )
		*buffer = objectInfo.GrantedAccess;

	if ( objectInfo.GrantedAccess & dangerousFlags ) {
		return true;
	}
	else {
		std::cout << "Handle seguro: 0x" << std::hex << handle << std::endl;
	}

	return false;
}


std::vector<_SYSTEM_HANDLE> Mem::Handle::DetectOpenHandlesToProcess( )
{
	DWORD currentProcessId = GetCurrentProcessId( );
	auto handles = GetHandles( );
	std::vector<_SYSTEM_HANDLE> handlesTous;

	for ( auto & handle : handles )
	{
		if ( handle.ProcessId != currentProcessId )
		{
			if ( handle.ProcessId == 0 || handle.ProcessId == 4 )
			{
				continue;
			}

			HANDLE processHandle = OpenProcess( PROCESS_DUP_HANDLE , FALSE , handle.ProcessId );

			if ( processHandle )
			{
				HANDLE duplicatedHandle = INVALID_HANDLE_VALUE;

				if ( DuplicateHandle( processHandle , ( HANDLE ) handle.Handle , GetCurrentProcess( ) , &duplicatedHandle , 0 , FALSE , DUPLICATE_SAME_ACCESS ) )
				{
					if ( GetProcessId( duplicatedHandle ) == currentProcessId )
					{
						handle.ReferencingUs = true;
						//Logger::logf( "UltimateAnticheat.log" , Detection , "Handle %d from process %d is referencing our process." , handle.Handle , handle.ProcessId );
						handlesTous.push_back( handle );
					}
					else
					{
						handle.ReferencingUs = false;
					}

					if ( duplicatedHandle != INVALID_HANDLE_VALUE )
						CloseHandle( duplicatedHandle );
				}

				CloseHandle( processHandle );
			}
			else
			{
				//Logger::logf("UltimateAnticheat.log", Warning, "Couldn't open process with id %d @ Handles::DetectOpenHandlesToProcess (possible LOCAL SERVICE or SYSTEM process)", handle.ProcessId);
				continue;
			}
		}
	}

	return handlesTous;
}


std::vector<ProcessInfo> Mem::Process::EnumerateProcesses( ) {
	std::vector<ProcessInfo> processesInfo;

	HANDLE hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS , 0 );
	if ( hProcessSnap == INVALID_HANDLE_VALUE ) {
		std::cerr << "Error: Unable to create snapshot of processes." << std::endl;
		return processesInfo;
	}

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof( PROCESSENTRY32 );

	if ( !Process32First( hProcessSnap , &pe32 ) ) {
		std::cerr << "Error: Unable to get first process." << std::endl;
		CloseHandle( hProcessSnap );
		return processesInfo;
	}

	do {

		ProcessInfo pInfo;
		pInfo.processID = pe32.th32ProcessID;
		pInfo.processName = pe32.szExeFile;
		pInfo.threadCount = pe32.cntThreads;

		// Obter classe de prioridade do processo
		HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ , FALSE , pInfo.processID );
		if ( hProcess ) {
			pInfo.priorityClass = GetPriorityClass( hProcess );
			CloseHandle( hProcess );
		}

		pInfo.threads = Mem::Thread::Get().EnumerateThreads( pInfo.processID );
		pInfo.modules = Mem::Module::Get( ).EnumerateModules( pInfo.processID );
		pInfo.openhandles = Mem::Handle::Get( ).EnumerateHandles( pInfo.processID );

		// Adicione o processo à lista
		processesInfo.push_back( pInfo );

	} while ( Process32Next( hProcessSnap , &pe32 ) );

	CloseHandle( hProcessSnap );
	return processesInfo;
}

ProcessInfo Mem::Process::GetProcessInfo( DWORD Pid ) {
	ProcessInfo processesInfo;

	if ( !Pid )
		return processesInfo;

	HANDLE hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS , 0 );
	if ( hProcessSnap == INVALID_HANDLE_VALUE ) {
		std::cerr << "Error: Unable to create snapshot of processes." << std::endl;
		return processesInfo;
	}

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof( PROCESSENTRY32 );

	if ( !Process32First( hProcessSnap , &pe32 ) ) {
		std::cerr << "Error: Unable to get first process." << std::endl;
		CloseHandle( hProcessSnap );
		return processesInfo;
	}

	do {
		if ( pe32.th32ProcessID != Pid )
			continue;

		ProcessInfo pInfo;
		pInfo.processID = pe32.th32ProcessID;
		pInfo.processName = pe32.szExeFile;
		pInfo.threadCount = pe32.cntThreads;

		// Obter classe de prioridade do processo
		HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ , FALSE , pInfo.processID );
		if ( hProcess ) {
			pInfo.priorityClass = GetPriorityClass( hProcess );
			CloseHandle( hProcess );
		}

		pInfo.threads = Mem::Thread::Get( ).EnumerateThreads( pInfo.processID );
		pInfo.modules = Mem::Module::Get( ).EnumerateModules( pInfo.processID );
		pInfo.openhandles = Mem::Handle::Get( ).EnumerateHandles( pInfo.processID );

		// Adicione o processo à lista
		return pInfo;

	} while ( Process32Next( hProcessSnap , &pe32 ) );


	return processesInfo;
}


ProcessInfo Mem::Process::GetProcessInfo( std::string Name) {
	ProcessInfo processesInfo;

	if ( Name.empty( ) )
		return processesInfo;

	HANDLE hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS , 0 );
	if ( hProcessSnap == INVALID_HANDLE_VALUE ) {
		std::cerr << "Error: Unable to create snapshot of processes." << std::endl;
		return processesInfo;
	}

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof( PROCESSENTRY32 );

	if ( !Process32First( hProcessSnap , &pe32 ) ) {
		std::cerr << "Error: Unable to get first process." << std::endl;
		CloseHandle( hProcessSnap );
		return processesInfo;
	}

	do {
		if ( pe32.szExeFile != Name.c_str( ) )
			continue;


		ProcessInfo pInfo;
		pInfo.processID = pe32.th32ProcessID;
		pInfo.processName = pe32.szExeFile;
		pInfo.threadCount = pe32.cntThreads;

		// Obter classe de prioridade do processo
		HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ , FALSE , pInfo.processID );
		if ( hProcess ) {
			pInfo.priorityClass = GetPriorityClass( hProcess );
			CloseHandle( hProcess );
		}

		pInfo.threads = Mem::Thread::Get( ).EnumerateThreads( pInfo.processID );
		pInfo.modules = Mem::Module::Get( ).EnumerateModules( pInfo.processID );
		pInfo.openhandles = Mem::Handle::Get( ).EnumerateHandles( pInfo.processID );

		// Adicione o processo à lista
		return pInfo;

	} while ( Process32Next( hProcessSnap , &pe32 ) );


	return processesInfo;
}




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

std::string Mem::GetProcessPath( DWORD processID ) {
	std::string processPath;
	HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ , FALSE , processID );

	if ( hProcess != NULL ) {
		char exePath[ MAX_PATH ];
		if ( GetModuleFileNameEx( hProcess , NULL , exePath , MAX_PATH ) ) {
			processPath = exePath;
			size_t lastBackslash = processPath.find_last_of( "\\" );
			if ( lastBackslash != std::string::npos ) {
				return processPath.substr( 0 , lastBackslash );
			}
		}
		CloseHandle( hProcess );
	}

	return processPath;
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

bool Mem::ProcessIsOnSystemFolder( int pid ) {
	std::string Path = GetProcessExecutablePath( pid );

	return Utils::Get( ).CheckStrings( Path , xorstr_( "\\System32\\" ) ) ||
		Utils::Get( ).CheckStrings( Path , xorstr_( "\\SysWOW64\\" ) ) ||
		Utils::Get( ).CheckStrings( Path , xorstr_( "\\system32\\" ) );
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


BOOL CALLBACK Mem::EnumWindowsProc( HWND hwnd , LPARAM lParam ) {
	std::vector<WindowInfo> * Windows = reinterpret_cast< std::vector<WindowInfo> * >( lParam );
	DWORD processId;
	GetWindowThreadProcessId( hwnd , &processId );


	Windows->push_back( { hwnd, processId } );
	return TRUE;
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



bool Mem::IsPIDRunning( DWORD dwPid ) {
	HANDLE Process = Mem::Get( ).GetProcessHandle( dwPid );

	if ( Process != NULL ) {
		CloseHandle( Process );
		return true;
	}

	CloseHandle( Process );
	return false;
}


#include "../../Process/Handles.hpp"

std::vector<_SYSTEM_HANDLE> Mem::Handle::GetHandles( )
{
	Handles::NtQuerySystemInformationFunc NtQuerySystemInformation = ( Handles::NtQuerySystemInformationFunc ) GetProcAddress( GetModuleHandleW( L"ntdll.dll" ) , xorstr_( "NtQuerySystemInformation" ) );
	if ( !NtQuerySystemInformation )
	{
		//Logger::logf( "UltimateAnticheat.log" , Err , "Could not get NtQuerySystemInformation function address @ Handles::GetHandles" );
		return {};
	}

	ULONG bufferSize = 0x10000;
	PVOID buffer = nullptr;
	NTSTATUS status = 0;

	do
	{
		buffer = malloc( bufferSize );
		if ( !buffer )
		{
			//Logger::logf( "UltimateAnticheat.log" , Err , "Memory allocation failed @ Handles::GetHandles" );
			return {};
		}

		status = NtQuerySystemInformation( ( Handles::SYSTEM_INFORMATION_CLASS ) 16 , buffer , bufferSize , &bufferSize );
		if ( status == STATUS_INFO_LENGTH_MISMATCH )
		{
			free( buffer );
			bufferSize *= 2;
		}
		else if ( !( ( ( NTSTATUS ) ( status ) ) >= 0 ) )
		{
			//Logger::logf( "UltimateAnticheat.log" , Err , "NtQuerySystemInformation failed @ Handles::GetHandles" );
			free( buffer );
			return {};
		}
	} while ( status == STATUS_INFO_LENGTH_MISMATCH );

	PSYSTEM_HANDLE_INFORMATION handleInfo = ( PSYSTEM_HANDLE_INFORMATION ) buffer;
	std::vector<SYSTEM_HANDLE> handles( handleInfo->Handles , handleInfo->Handles + handleInfo->HandleCount );
	free( buffer );
	return handles;
}