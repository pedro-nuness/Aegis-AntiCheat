#ifndef MEMORY_H
#define MEMORY_H

#include <vector>
#include <string>
#include <windows.h>
#include "../Utils/singleton.h" // Incluindo o cabeçalho do Singleton


class Mem : public CSingleton<Mem> {
public:
    std::string ConvertWchar( WCHAR inCharText[ 260 ] );
    std::vector<std::string> GetModules( DWORD processID );
    bool CheckModule( int ID , std::string bModule );
    void WaitModule( int PID , std::string Module );
    DWORD GetProcessID( LPCTSTR ProcessName );
    uintptr_t GetModule( const std::string & ModuleName , int processID );
    uintptr_t GetModuleBaseAddress( std::string  lpszModuleName, DWORD PID );
    DWORD GetModuleSize( std::string lpszModuleName , DWORD PID );
    uintptr_t GetAddressFromSignature( DWORD PID, std::string module_name, std::vector<int> signature );
    HANDLE GetProcessHandle( DWORD PID );
    std::vector<std::string> EnumAllWindows( );
    std::vector<std::string> EnumAllProcesses( );
    static char asciitolower( char in );
    bool ReadFileToMemory( const std::string & file_path , std::vector<uint8_t> * out_buffer );
    std::string  GetFileHash( std::string path );
    bool IsPIDRunning( DWORD PID );
    std::string GetProcessName( DWORD PID );

};

#endif // MEMORY_H