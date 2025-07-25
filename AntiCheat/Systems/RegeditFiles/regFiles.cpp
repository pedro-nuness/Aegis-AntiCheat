#include "regFiles.h"
#include <iostream>
#include <Windows.h>

#include "../Utils/xorstr.h"

regFiles _regfiles;

std::string portPath = xorstr_( "Software\\AegisPort" );

bool regFiles::savePort( std::string porta ) {
	HKEY hKey;

	// Cria ou abre a chave no registro
	if ( RegCreateKeyExA( HKEY_CURRENT_USER , portPath.c_str( ) , 0 , nullptr , 0 , KEY_WRITE , nullptr , &hKey , nullptr ) == ERROR_SUCCESS ) {
		// Escreve o valor da porta como string
		RegSetValueExA( hKey , xorstr_( "Porta" ) , 0 , REG_SZ , reinterpret_cast< const BYTE * >( porta.c_str( ) ) , porta.size( ) + 1 );
		RegCloseKey( hKey );
		return true;
	}

	return false;
}

int regFiles::readPort( ) {
	HKEY hKey;
	char buffer[ 256 ];
	DWORD bufferSize = sizeof( buffer );
	DWORD tipo = 0;

	if ( RegOpenKeyExA( HKEY_CURRENT_USER , portPath.c_str( ) , 0 , KEY_READ , &hKey ) == ERROR_SUCCESS ) {
		if ( RegQueryValueExA( hKey , xorstr_( "Porta" ) , nullptr , &tipo , reinterpret_cast< LPBYTE >( buffer ) , &bufferSize ) == ERROR_SUCCESS ) {
			if ( tipo == REG_SZ ) {
				RegCloseKey( hKey );
				return std::stoi( buffer );
			}
		}
		RegCloseKey( hKey );
	}

	return 0;
}
