#include "hardware.h"


#define WIN32_LEAN_AND_MEAN // Evita a inclus�o de winsock.h pelo windows.h
#include <winsock2.h>       // Inclua winsock2.h antes de windows.h
#include <windows.h>        // Inclua windows.h depois de winsock2.h
#include <ws2tcpip.h>       // Inclua ws2tcpip.h para fun��es de rede adicionais
#include <iphlpapi.h>       // Inclua iphlpapi.h para fun��es de rede do IP Helper API

// Outras bibliotecas de terceiros
#include <iostream>
#include <string>
#include <vector>

// Inclui as APIs do Windows
#include <comdef.h>
#include <Wbemidl.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>

// Inclui bibliotecas de terceiros ou utilit�rios
#include <iostream>
#include <string>
#include <vector>
#include <regex>

// Bibliotecas adicionais (caso necess�rio)
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "comsuppw.lib")


#include "../../Systems/LogSystem/File/File.h"
#include "../../Systems/LogSystem/Log.h"
#include "../../Systems/Memory/memory.h"

#include "../Utils/xorstr.h"
#include "../Utils/utils.h"

#include "../Utils/StringCrypt/StringCrypt.h"

#include <nlohmann/json.hpp>

using json = nlohmann::json;

CryptedString CachedMotherBoardSerialNumber;
CryptedString CachedDiskSerialNumber;
std::vector<CryptedString> CachedMac;
CryptedString CachedIp;
CryptedString CachedUniqueID;
CryptedString CachedVersionID;




void hardware::GenerateInitialCache( ) {
	GetMotherboardSerialNumber( nullptr );
	GetDiskSerialNumber( nullptr );
}

void hardware::EndCacheGeneration( ) {
	getMacAddress( );
	GetIp( );
	GetVersionUID( nullptr );
}


class ComInitializer {
public:
	ComInitializer( ) {
		HRESULT hr = CoInitializeEx( nullptr , COINIT_MULTITHREADED );
		if ( FAILED( hr ) ) throw std::runtime_error( "Failed to initialize COM library" );
	}
	~ComInitializer( ) { CoUninitialize( ); }
};

class WmiService {
	IWbemLocator * pLoc = nullptr;
	IWbemServices * pSvc = nullptr;

public:
	WmiService( ) {
		HRESULT hr = CoCreateInstance( CLSID_WbemLocator , nullptr , CLSCTX_INPROC_SERVER ,
			IID_IWbemLocator , reinterpret_cast< void ** >( &pLoc ) );
		if ( FAILED( hr ) ) throw std::runtime_error( "Failed to create IWbemLocator object" );

		hr = pLoc->ConnectServer( bstr_t( L"ROOT\\CIMV2" ) , nullptr , nullptr , 0 , NULL , 0 , 0 , &pSvc );
		if ( FAILED( hr ) ) throw std::runtime_error( "Failed to connect to WMI namespace" );

		hr = CoSetProxyBlanket( pSvc , RPC_C_AUTHN_WINNT , RPC_C_AUTHZ_NONE , nullptr ,
			RPC_C_AUTHN_LEVEL_CALL , RPC_C_IMP_LEVEL_IMPERSONATE , nullptr , EOAC_NONE );
		if ( FAILED( hr ) ) throw std::runtime_error( "Failed to set proxy blanket" );
	}

	~WmiService( ) {
		if ( pSvc ) pSvc->Release( );
		if ( pLoc ) pLoc->Release( );
	}

	IWbemServices * GetService( ) const { return pSvc; }
};

std::string QueryWmiSerialNumber( IWbemServices * pSvc , const std::wstring & query , const std::wstring & property ) {
	IEnumWbemClassObject * pEnumerator = nullptr;
	HRESULT hr = pSvc->ExecQuery( bstr_t( L"WQL" ) , bstr_t( query.c_str( ) ) ,
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY , nullptr , &pEnumerator );
	if ( FAILED( hr ) ) throw std::runtime_error( "WMI query failed" );

	IWbemClassObject * pclsObj = nullptr;
	ULONG uReturn = 0;
	std::string result;

	if ( pEnumerator->Next( WBEM_INFINITE , 1 , &pclsObj , &uReturn ) == S_OK && uReturn > 0 ) {
		VARIANT vtProp;
		hr = pclsObj->Get( property.c_str( ) , 0 , &vtProp , nullptr , nullptr );
		if ( SUCCEEDED( hr ) ) {
			result = _bstr_t( vtProp.bstrVal );
			VariantClear( &vtProp );
		}
		pclsObj->Release( );
	}
	pEnumerator->Release( );
	return result;
}

bool hardware::GetMotherboardSerialNumber( std::string * buffer ) {
	if ( !CachedMotherBoardSerialNumber.EncryptedString.empty( ) && buffer ) {
		std::string * Str = StringCrypt::Get( ).DecryptString( CachedMotherBoardSerialNumber );
		*buffer = *Str;
		StringCrypt::Get( ).CleanString( Str );
		return true;
	}

	try {
		ComInitializer comInit;
		WmiService wmiService;
		auto serial = QueryWmiSerialNumber( wmiService.GetService( ) ,
			L"SELECT SerialNumber FROM Win32_BaseBoard" ,
			L"SerialNumber" );
		CachedMotherBoardSerialNumber = StringCrypt::Get( ).EncryptString( serial );
		if ( buffer ) *buffer = serial;
		return true;
	}
	catch ( const std::exception & ex ) {
		LogSystem::Get( ).ConsoleLog( _HWID , ex.what( ) , RED );
		return false;
	}
}

bool hardware::GetVersionUID( std::string * buffer ) {
	if ( !CachedVersionID.EncryptedString.empty( ) && buffer ) {
		std::string * Str = StringCrypt::Get( ).DecryptString( CachedVersionID );
		*buffer = *Str;
		StringCrypt::Get( ).CleanString( Str );
		return true;
	}

	{
		std::string VersionID = Mem::Get( ).GetFileHash( Mem::Get( ).GetProcessExecutablePath( GetCurrentProcessId( ) ) );
		CachedVersionID = StringCrypt::Get( ).EncryptString( VersionID );
	}
}

bool hardware::GetUniqueUID( std::string * buffer , std::string ID ) {
	if ( buffer == nullptr ) {
		if ( ID.empty( ) || !CachedUniqueID.EncryptedString.empty( ) )
			return false;
		CachedUniqueID = StringCrypt::Get( ).EncryptString( ID );
		return true;
	}

	if ( !CachedUniqueID.EncryptedString.empty( ) && buffer ) {
		std::string * Str = StringCrypt::Get( ).DecryptString( CachedUniqueID );
		*buffer = *Str;
		StringCrypt::Get( ).CleanString( Str );
		return true;
	}

	return false;
}

bool hardware::GetDiskSerialNumber( std::string * buffer ) {
	if ( !CachedDiskSerialNumber.EncryptedString.empty( ) && buffer ) {
		std::string * Str = StringCrypt::Get( ).DecryptString( CachedDiskSerialNumber );
		*buffer = *Str;
		StringCrypt::Get( ).CleanString( Str );
		return true;
	}

	try {
		ComInitializer comInit;
		WmiService wmiService;
		auto serial = QueryWmiSerialNumber( wmiService.GetService( ) ,
			L"SELECT SerialNumber FROM Win32_DiskDrive" ,
			L"SerialNumber" );
		CachedDiskSerialNumber = StringCrypt::Get( ).EncryptString( serial );
		if ( buffer ) *buffer = serial;
		return true;
	}
	catch ( const std::exception & ex ) {
		LogSystem::Get( ).ConsoleLog( _HWID , ex.what( ) , RED );
		return false;
	}
}
std::string checkRegistryForSteamPath( ) {
	HKEY hKey;
	std::string path = xorstr_( "SOFTWARE\\Valve\\Steam" );
	char steamPath[ MAX_PATH ];
	DWORD pathSize = sizeof( steamPath );

	if ( RegOpenKeyExA( HKEY_CURRENT_USER , path.c_str( ) , 0 , KEY_READ , &hKey ) == ERROR_SUCCESS ) {
		if ( RegQueryValueExA( hKey , xorstr_( "SteamPath" ) , nullptr , nullptr , ( LPBYTE ) steamPath , &pathSize ) == ERROR_SUCCESS ) {
			RegCloseKey( hKey );
			return std::string( steamPath );
		}
		RegCloseKey( hKey );
	}
	return "";
}

std::vector<std::string> extractUserIds( const std::string & rawInput ) {
	std::string processed = rawInput;

	// Remove quebras de linha e tabula��es
	processed = std::regex_replace( processed , std::regex( xorstr_( "[\\r\\n]+" ) ) , " " );
	processed = std::regex_replace( processed , std::regex( xorstr_( "[\\t]+" ) ) , " " );

	// Remove m�ltiplos espa�os em branco
	processed = std::regex_replace( processed , std::regex( xorstr_( " +" ) ) , " " );

	// Extrai os IDs de usu�rio
	std::vector<std::string> userIds;
	std::regex userIdRegex( "\"([0-9]+)\"\\s*\\{" );
	std::smatch matches;

	while ( std::regex_search( processed , matches , userIdRegex ) ) {
		userIds.push_back( matches[ 1 ] ); // Adiciona o ID ao vetor
		processed = matches.suffix( ).str( ); // Continua a buscar ap�s o ID encontrado
	}

	// Constr�i o JSON a partir dos IDs extra�dos
	nlohmann::json jsonOutput;

	return userIds; // Retorna o JSON como string
}

bool hardware::GetLoggedUsers( std::vector<std::string> * Buffer ) {


	std::string SteamPath = checkRegistryForSteamPath( );
	if ( SteamPath.empty( ) ) {
		LogSystem::Get( ).ConsoleLog( _CHECKER , xorstr_( "failed to get steam path" ) , RED );
		return false;
	}

	std::string LoginUsers = SteamPath + xorstr_( "\\config\\loginusers.vdf" );
	File LoginUsersFile( LoginUsers );
	if ( !LoginUsersFile.Exists( ) ) {
		LogSystem::Get( ).ConsoleLog( _CHECKER , xorstr_( "can't find loginusers" ) , RED );
		return false;
	}

	std::string LoginUsersFileContent = LoginUsersFile.Read( );
	if ( LoginUsersFileContent.empty( ) )
	{
		LogSystem::Get( ).ConsoleLog( _CHECKER , xorstr_( "loggin users empty!" ) , RED );
		return false;
	}

	if ( Buffer != nullptr ) {
		*Buffer = extractUserIds( LoginUsersFileContent );
	}

	return true;
}

std::vector<std::string> hardware::getMacAddress( ) {
	std::vector < std::string > MACS;
	if ( !CachedMac.empty( ) ) {
		for ( CryptedString & CryptedMac : CachedMac ) {
			std::string * Str = StringCrypt::Get( ).DecryptString( CryptedMac );
			MACS.emplace_back( *Str );
			StringCrypt::Get( ).CleanString( Str );
		}
		return MACS;
	}

	IP_ADAPTER_INFO AdapterInfo[ 16 ];              // Aloca informa��es para at� 16 NICs
	DWORD dwBufLen = sizeof( AdapterInfo );         // Salva o tamanho da mem�ria de AdapterInfo
	DWORD dwStatus = GetAdaptersInfo( AdapterInfo , &dwBufLen );
	if ( dwStatus != ERROR_SUCCESS ) {
		LogSystem::Get( ).ConsoleLog( _HWID , xorstr_( "GetAdaptersInfo failed with error:" ) , RED );
		return MACS;
	}

	PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;  // Ponteiro para a informa��o do adaptador atual
	char macAddr[ 18 ];

	while ( pAdapterInfo ) {
		// Formata o endere�o MAC
		sprintf_s( macAddr , sizeof( macAddr ) , "%02X:%02X:%02X:%02X:%02X:%02X" ,
			pAdapterInfo->Address[ 0 ] , pAdapterInfo->Address[ 1 ] ,
			pAdapterInfo->Address[ 2 ] , pAdapterInfo->Address[ 3 ] ,
			pAdapterInfo->Address[ 4 ] , pAdapterInfo->Address[ 5 ] );

		// Retorna o endere�o MAC do primeiro adaptador encontrado
		MACS.emplace_back( macAddr );
		pAdapterInfo = pAdapterInfo->Next;  // Move para o pr�ximo adaptador
	}

	for ( auto MAC : MACS )
		CachedMac.emplace_back( StringCrypt::Get( ).EncryptString( MAC ) );

	return MACS;
}

std::string hardware::GetIp( ) {
	if ( CachedIp.EncryptedString.empty( ) ) {
		json js;
		try {
			js = json::parse( Utils::Get( ).DownloadString( xorstr_( "https://httpbin.org/ip" ) ) );
		}
		catch ( const json::parse_error & e ) {
			std::cout << xorstr_( "Failed to parse JSON: " ) << e.what( ) << std::endl;
			return "";
		}

		CachedIp = StringCrypt::Get( ).EncryptString( js[ xorstr_( "origin" ) ] );
		return js[ xorstr_( "origin" ) ];
	}
	std::string * str = StringCrypt::Get( ).DecryptString( CachedIp );
	std::string result = *str;
	StringCrypt::Get( ).CleanString( str );


	return result;
}
