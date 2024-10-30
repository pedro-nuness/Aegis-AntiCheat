#include "memory.h"

#include <string>
#include <Windows.h>
#include <Psapi.h>
#include <locale>
#include <codecvt>


// Função auxiliar para converter std::string para std::wstring
std::wstring ConvertToWString( const std::string & str ) {
    // Determinar o tamanho necessário para a string wide
    int sizeNeeded = MultiByteToWideChar( CP_UTF8 , 0 , str.c_str( ) , -1 , NULL , 0 );
    std::wstring wideString( sizeNeeded , 0 );
    // Converter a string
    MultiByteToWideChar( CP_UTF8 , 0 , str.c_str( ) , -1 , &wideString[ 0 ] , sizeNeeded );
    return wideString;
}

std::string memory::GetProcessPath( DWORD processID ) {
    std::wstring processPath;
    HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ , FALSE , processID );

    if ( hProcess != NULL ) {
        wchar_t exePath[ MAX_PATH ];
        if ( GetModuleFileNameExW( hProcess , NULL , exePath , MAX_PATH ) ) {
            processPath = exePath;
            size_t lastBackslash = processPath.find_last_of( L"\\" );
            if ( lastBackslash != std::wstring::npos ) {
                CloseHandle( hProcess );
                processPath = processPath.substr( 0 , lastBackslash );
            }
        }
        CloseHandle( hProcess );
    }

    // Converter wstring para string (Unicode para multibyte)
    std::string result;
    int sizeNeeded = WideCharToMultiByte( CP_UTF8 , 0 , processPath.c_str( ) , -1 , NULL , 0 , NULL , NULL );
    if ( sizeNeeded > 0 ) {
        result.resize( sizeNeeded - 1 ); // -1 para remover o caractere nulo
        WideCharToMultiByte( CP_UTF8 , 0 , processPath.c_str( ) , -1 , &result[ 0 ] , sizeNeeded , NULL , NULL );
    }

    return result;
}