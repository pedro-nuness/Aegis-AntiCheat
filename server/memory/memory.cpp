#include "memory.h"

#include <string>
#include <Windows.h>
#include <Psapi.h>
#include <locale>
#include <codecvt>
#include <fstream>

#include "sha1.h"

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

bool memory::ReadFileToMemory( const std::string & file_path , std::vector<uint8_t> * out_buffer )
{
    std::ifstream file_ifstream( file_path , std::ios::binary );

    if ( !file_ifstream )
        return false;

    out_buffer->assign( ( std::istreambuf_iterator<char>( file_ifstream ) ) , std::istreambuf_iterator<char>( ) );
    file_ifstream.close( );

    return true;
}

std::string memory::GetProcessExecutablePath( DWORD processID ) {
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

std::string memory::GetFileHash( std::string path )
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


std::string memory::GenerateHash( std::string msg ) {
    SHA1 sha1;
    sha1.add( msg.data( ) , msg.size( ) );
    return sha1.getHash( );
}
