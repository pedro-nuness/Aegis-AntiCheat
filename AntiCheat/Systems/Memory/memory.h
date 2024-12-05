#ifndef MEMORY_H
#define MEMORY_H

#include <vector>
#include <string>
#include <windows.h>
#include "../Utils/singleton.h" // Incluindo o cabeçalho do Singleton
#include "../../Process/Imports.h"

struct MemoryRegion {
	LPVOID baseAddress;
	SIZE_T size;
	std::vector<BYTE> buffer;
};

struct WindowInfo {
	HWND hwnd;
	DWORD processId;
};



class Mem : public CSingleton<Mem> {
public:

	class Thread : public CSingleton<Thread> {
	public:
		std::vector< ThreadInfo> EnumerateThreads( DWORD processID );
	};

	class Module : public CSingleton<Module> {
	public:
		std::vector< ModuleInfo> EnumerateModules( DWORD processID );
	};

	class Handle : public CSingleton<Handle> {
	public:
		std::vector<_SYSTEM_HANDLE> EnumerateHandles( DWORD processID );
		std::vector<_SYSTEM_HANDLE> DetectOpenHandlesToProcess( );
		std::vector<_SYSTEM_HANDLE> GetHandles( );
		bool CheckDangerousPermissions( HANDLE handle , DWORD * buffer );
	};

	class Process : public CSingleton<Process> {
	public:
		std::vector< ProcessInfo> EnumerateProcesses( );
		ProcessInfo GetProcessInfo( std::string ProcessName );
		ProcessInfo GetProcessInfo( DWORD Pid );
	};



	void SaveFunctionBytesToFile(  void * funcAddress , size_t numBytes ,  std::string  outputFileName );
	std::vector<SYSTEM_HANDLE> GetHandlesForProcess( DWORD processId );
	bool RestrictProcessAccess( );
	std::string ConvertWchar( WCHAR inCharText[ 260 ] );
	std::vector<std::string> GetModules( DWORD processID );
	std::string GetProcessExecutablePath( DWORD processID );
	std::string GetProcessPath( DWORD processID );
	bool VerifySignature( HANDLE hProcess );
	bool ProcessIsOnSystemFolder( int PID );
	float GetProcessMemoryUsage( DWORD processID );
	bool CheckModule( int ID , std::string bModule );
	void WaitModule( int PID , std::string Module );
	DWORD GetProcessID( LPCTSTR ProcessName );
	uintptr_t GetModule( const std::string & ModuleName , int processID );
	uintptr_t GetModuleBaseAddress( std::string  lpszModuleName , DWORD PID );
	DWORD GetModuleSize( std::string lpszModuleName , DWORD PID );
	uintptr_t GetAddressFromSignature( DWORD PID , std::string module_name , std::vector<int> signature );
	HANDLE GetProcessHandle( DWORD PID );
	std::vector<std::string> EnumAllWindows( );
	bool IsSystemProcess( HANDLE Process );
	std::vector<std::string> EnumAllProcesses( );
	static char asciitolower( char in );
	bool ReadFileToMemory( const std::string & file_path , std::vector<uint8_t> * out_buffer );
	std::string  GetFileHash( std::string path );
	std::string  GenerateHash( std::string str );
	std::string  GenerateVecCharHash( std::vector<char> msg );
	bool IsPIDRunning( DWORD PID );
	std::string GetProcessName( DWORD PID );
	bool DumpProcessMemory( HANDLE hProcess , std::vector<MemoryRegion> & memoryDump );
	static BOOL CALLBACK EnumWindowsProc( HWND hwnd , LPARAM lParam );
	std::vector<std::pair<std::string , LPVOID>> SearchStringsInDump( const std::vector<MemoryRegion> & memoryDump , std::vector< std::string> & searchStrings );
	std::vector<std::pair<std::string , LPVOID>> DumpAndSearch( HANDLE hProcess , std::vector< std::string> & searchStrings );
	bool SearchStringInDump( const std::vector<MemoryRegion> & memoryDump , const std::string & searchString );

};

#endif // MEMORY_H