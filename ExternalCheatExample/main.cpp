
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <psapi.h>
#include "json/json.hpp"

#include <VersionHelpers.h>

using json = nlohmann::json;

std::string GetProcessName( DWORD processID ) {
    char processName[ MAX_PATH ] = "<unknown>";
    HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ , FALSE , processID );
    if ( hProcess != NULL ) {
        HMODULE hMod;
        DWORD cbNeeded;
        if ( EnumProcessModules( hProcess , &hMod , sizeof( hMod ) , &cbNeeded ) ) {
            GetModuleBaseNameA( hProcess , hMod , processName , sizeof( processName ) / sizeof( char ) );
        }
        CloseHandle( hProcess );
    }
    return std::string( processName );
}

std::vector<std::string> GetRunningProcesses( ) {
    std::vector<std::string> processes;
    DWORD aProcesses[ 1024 ] , cbNeeded , cProcesses;

    if ( EnumProcesses( aProcesses , sizeof( aProcesses ) , &cbNeeded ) ) {
        cProcesses = cbNeeded / sizeof( DWORD );
        for ( unsigned int i = 0; i < cProcesses; i++ ) {
            if ( aProcesses[ i ] != 0 ) {
                std::string processName = GetProcessName( aProcesses[ i ] );
                processes.push_back( processName );
            }
        }
    }
    return processes;
}

std::vector<std::string> GetLoadedDrivers( ) {
    std::vector<std::string> drivers;

    // Número máximo de drivers
    DWORD dwBytesNeeded;
    DWORD dwDriverCount;

    // Obter o número de drivers carregados no sistema
    if ( EnumDeviceDrivers( NULL , 0 , &dwBytesNeeded ) ) {
        dwDriverCount = dwBytesNeeded / sizeof( void * );
        std::vector<void *> driverPtrs( dwDriverCount );

        // Enumera os drivers carregados
        if ( EnumDeviceDrivers( driverPtrs.data( ) , dwBytesNeeded , &dwBytesNeeded ) ) {
            for ( DWORD i = 0; i < dwDriverCount; ++i ) {
                char szDriverName[ MAX_PATH ];
                // Pega o nome base do driver
                if ( GetDeviceDriverBaseNameA( driverPtrs[ i ] , szDriverName , MAX_PATH ) ) {
                    drivers.push_back( std::string( szDriverName ) );
                }
            }
        }
    }

    return drivers;
}
void GetOSVersion( json & dump ) {
    if ( IsWindows10OrGreater( ) ) {
        dump[ "os" ] = "Windows 10 or greater";
    }
    else if ( IsWindows8OrGreater( ) ) {
        dump[ "os" ] = "Windows 8 or greater";
    }
    else if ( IsWindows7OrGreater( ) ) {
        dump[ "os" ] = "Windows 7 or greater";
    }
    else {
        dump[ "os" ] = "Older Windows version";
    }
}

json GetSystemInfoDump( ) {
    json dump;

    // Process List
    dump[ "processes" ] = GetRunningProcesses( );

    // Drivers List
    dump[ "drivers" ] = GetLoadedDrivers( );

    // Get Memory Information
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof( MEMORYSTATUSEX );
    GlobalMemoryStatusEx( &memStatus );
    dump[ "memory" ] = {
        {"total", memStatus.ullTotalPhys},
        {"available", memStatus.ullAvailPhys}
    };

    // CPU Information (simplified)
    SYSTEM_INFO sysInfo;
    GetSystemInfo( &sysInfo );
    dump[ "cpu" ] = {
        {"processor_architecture", sysInfo.wProcessorArchitecture},
        {"number_of_processors", sysInfo.dwNumberOfProcessors}
    };

    // Get OS Version
    GetOSVersion( dump );

    return dump;
}

void SaveToJsonFile( const json & data , const std::string & filename ) {
    std::ofstream file( filename );
    if ( file.is_open( ) ) {
        file << data.dump( 4 ); // Pretty print JSON with 4 spaces
        file.close( );
    }
    else {
        std::cerr << "Failed to open the file for writing." << std::endl;
    }
}

int main( ) {
    json systemDump = GetSystemInfoDump( );
    SaveToJsonFile( systemDump , "dump.txt" );

    std::cout << "System dump saved to dump.txt" << std::endl;
    return 0;
}
