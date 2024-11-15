#include "hardware.h"


#define WIN32_LEAN_AND_MEAN // Evita a inclusão de winsock.h pelo windows.h
#include <winsock2.h>       // Inclua winsock2.h antes de windows.h
#include <windows.h>        // Inclua windows.h depois de winsock2.h
#include <ws2tcpip.h>       // Inclua ws2tcpip.h para funções de rede adicionais
#include <iphlpapi.h>       // Inclua iphlpapi.h para funções de rede do IP Helper API

// Outras bibliotecas de terceiros
#include <iostream>
#include <string>
#include <vector>

// Inclui as APIs do Windows
#include <comdef.h>
#include <Wbemidl.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>

// Inclui bibliotecas de terceiros ou utilitários
#include <iostream>
#include <string>
#include <vector>
#include <regex>

// Bibliotecas adicionais (caso necessário)
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "comsuppw.lib")


#include "../../Systems/LogSystem/File/File.h"
#include "../../Systems/LogSystem/Log.h"

#include "../Utils/xorstr.h"
#include "../Utils/utils.h"

#include "../Utils/StringCrypt/StringCrypt.h"

#include <nlohmann/json.hpp>

using json = nlohmann::json;

CryptedString CachedMotherBoardSerialNumber;
CryptedString CachedDiskSerialNumber;
std::vector<CryptedString> CachedMac;
CryptedString CachedIp;


void hardware::GenerateCache( ) {
	GetMotherboardSerialNumber(nullptr );
	GetDiskSerialNumber( nullptr );
	getMacAddress( );
	GetIp( );
}

bool hardware::GetMotherboardSerialNumber( std::string * buffer ) {
	if ( !CachedMotherBoardSerialNumber.EncryptedString.empty( ) && buffer != nullptr ) {
		std::string * Str = StringCrypt::Get( ).DecryptString( CachedMotherBoardSerialNumber );
		*buffer = *Str;
		StringCrypt::Get( ).CleanString( Str );
		return true;
	}

	HRESULT hres;

	// Inicializa o COM
	hres = CoInitializeEx( 0 , COINIT_MULTITHREADED );
	if ( FAILED( hres ) ) {
		LogSystem::Get( ).ConsoleLog( _HWID , xorstr_( "Failed to initialize COM library" ) , RED );
		return false;
	}

	// Define os níveis de segurança do COM
	hres = CoInitializeSecurity(
		nullptr , -1 , nullptr , nullptr ,
		RPC_C_AUTHN_LEVEL_DEFAULT ,
		RPC_C_IMP_LEVEL_IMPERSONATE ,
		nullptr , EOAC_NONE , nullptr );

	if ( FAILED( hres ) ) {
		CoUninitialize( );
		LogSystem::Get( ).ConsoleLog( _HWID , xorstr_( "Failed to initialize security" ) , RED );
		return false;
	}

	// Obtém o ponteiro para o serviço WMI
	IWbemLocator * pLoc = nullptr;

	hres = CoCreateInstance(
		CLSID_WbemLocator , 0 ,
		CLSCTX_INPROC_SERVER ,
		IID_IWbemLocator , ( LPVOID * ) &pLoc );

	if ( FAILED( hres ) ) {
		CoUninitialize( );
		LogSystem::Get( ).ConsoleLog( _HWID , xorstr_( "Failed to create IWbemLocator object" ) , RED );
		return false;
	}

	IWbemServices * pSvc = nullptr;

	// Conecta-se ao namespace root\cimv2
	hres = pLoc->ConnectServer(
		_bstr_t( L"ROOT\\CIMV2" ) , nullptr , nullptr , 0 ,
		NULL , 0 , 0 , &pSvc );

	if ( FAILED( hres ) ) {
		pLoc->Release( );
		CoUninitialize( );
		LogSystem::Get( ).ConsoleLog( _HWID , xorstr_( "Could not connect to WMI namespace" ) , RED );
		return false;
	}

	// Define os níveis de segurança do proxy
	hres = CoSetProxyBlanket(
		pSvc , RPC_C_AUTHN_WINNT , RPC_C_AUTHZ_NONE , nullptr ,
		RPC_C_AUTHN_LEVEL_CALL , RPC_C_IMP_LEVEL_IMPERSONATE ,
		nullptr , EOAC_NONE );

	if ( FAILED( hres ) ) {
		pSvc->Release( );
		pLoc->Release( );
		CoUninitialize( );
		LogSystem::Get( ).ConsoleLog( _HWID , xorstr_( "Could not set proxy blanket" ) , RED );
		return false;
	}

	// Faz a consulta WMI
	IEnumWbemClassObject * pEnumerator = nullptr;
	hres = pSvc->ExecQuery(
		bstr_t( xorstr_( "WQL" ) ) ,
		bstr_t( xorstr_( "SELECT SerialNumber FROM Win32_BaseBoard" ) ) ,
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY ,
		nullptr ,
		&pEnumerator );

	if ( FAILED( hres ) ) {
		pSvc->Release( );
		pLoc->Release( );
		CoUninitialize( );
		LogSystem::Get( ).ConsoleLog( _HWID , xorstr_( "Query for motherboard serial number failed" ) , RED );
		return false;
	}

	IWbemClassObject * pclsObj = nullptr;
	ULONG uReturn = 0;
	std::string serialNumber;

	while ( pEnumerator ) {
		HRESULT hr = pEnumerator->Next( WBEM_INFINITE , 1 , &pclsObj , &uReturn );
		if ( 0 == uReturn ) {
			break;
		}

		VARIANT vtProp;
		hr = pclsObj->Get( L"SerialNumber" , 0 , &vtProp , nullptr , nullptr );
		if ( SUCCEEDED( hr ) ) {
			serialNumber = _bstr_t( vtProp.bstrVal );
			VariantClear( &vtProp );
		}

		pclsObj->Release( );
	}

	// Libera recursos
	pSvc->Release( );
	pLoc->Release( );
	pEnumerator->Release( );
	CoUninitialize( );

	CachedMotherBoardSerialNumber = StringCrypt::Get( ).EncryptString( serialNumber );

	if ( buffer != nullptr )
		*buffer = serialNumber;
	return true;
}

bool hardware::GetDiskSerialNumber( std::string * buffer ) {
	if ( !CachedDiskSerialNumber.EncryptedString.empty( ) && buffer != nullptr ) {
		std::string * Str = StringCrypt::Get( ).DecryptString( CachedDiskSerialNumber );
		*buffer = *Str;
		StringCrypt::Get( ).CleanString( Str );
		return true;
	}


	HRESULT hres;

	// Inicializa o COM
	hres = CoInitializeEx( 0 , COINIT_MULTITHREADED );
	if ( FAILED( hres ) ) {
		LogSystem::Get( ).ConsoleLog( _HWID , xorstr_( "Failed to initialize COM library" ) , RED );
		return false;
	}

	// Define os níveis de segurança do COM
	hres = CoInitializeSecurity(
		nullptr , -1 , nullptr , nullptr ,
		RPC_C_AUTHN_LEVEL_DEFAULT ,
		RPC_C_IMP_LEVEL_IMPERSONATE ,
		nullptr , EOAC_NONE , nullptr );

	if ( FAILED( hres ) ) {
		CoUninitialize( );
		LogSystem::Get( ).ConsoleLog( _HWID , xorstr_( "Failed to initialize security" ) , RED );
		return false;
	}

	// Obtém o ponteiro para o serviço WMI
	IWbemLocator * pLoc = nullptr;

	hres = CoCreateInstance(
		CLSID_WbemLocator , 0 ,
		CLSCTX_INPROC_SERVER ,
		IID_IWbemLocator , ( LPVOID * ) &pLoc );

	if ( FAILED( hres ) ) {
		CoUninitialize( );
		LogSystem::Get( ).ConsoleLog( _HWID , xorstr_( "Failed to create IWbemLocator object" ) , RED );
		return false;
	}

	IWbemServices * pSvc = nullptr;

	// Conecta-se ao namespace root\cimv2
	hres = pLoc->ConnectServer(
		_bstr_t( L"ROOT\\CIMV2" ) , nullptr , nullptr , 0 ,
		NULL , 0 , 0 , &pSvc );

	if ( FAILED( hres ) ) {
		pLoc->Release( );
		CoUninitialize( );
		LogSystem::Get( ).ConsoleLog( _HWID , xorstr_( "Could not connect to WMI namespace" ) , RED );
		return false;
	}

	// Define os níveis de segurança do proxy
	hres = CoSetProxyBlanket(
		pSvc , RPC_C_AUTHN_WINNT , RPC_C_AUTHZ_NONE , nullptr ,
		RPC_C_AUTHN_LEVEL_CALL , RPC_C_IMP_LEVEL_IMPERSONATE ,
		nullptr , EOAC_NONE );

	if ( FAILED( hres ) ) {
		pSvc->Release( );
		pLoc->Release( );
		CoUninitialize( );
		LogSystem::Get( ).ConsoleLog( _HWID , xorstr_( "Could not set proxy blanket" ) , RED );
		return false;
	}

	// Faz a consulta WMI
	IEnumWbemClassObject * pEnumerator = nullptr;
	hres = pSvc->ExecQuery(
		bstr_t( xorstr_( "WQL" ) ) ,
		bstr_t( xorstr_( "SELECT SerialNumber FROM Win32_DiskDrive" ) ) ,
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY ,
		nullptr ,
		&pEnumerator );

	if ( FAILED( hres ) ) {
		pSvc->Release( );
		pLoc->Release( );
		CoUninitialize( );
		LogSystem::Get( ).ConsoleLog( _HWID , xorstr_( "Query for disk drive serial number failed" ) , RED );
		return false;
	}

	IWbemClassObject * pclsObj = nullptr;
	ULONG uReturn = 0;
	std::string serialNumber;

	while ( pEnumerator ) {
		HRESULT hr = pEnumerator->Next( WBEM_INFINITE , 1 , &pclsObj , &uReturn );
		if ( 0 == uReturn ) {
			break;
		}

		VARIANT vtProp;
		hr = pclsObj->Get( L"SerialNumber" , 0 , &vtProp , nullptr , nullptr );
		if ( SUCCEEDED( hr ) ) {
			serialNumber = _bstr_t( vtProp.bstrVal );
			VariantClear( &vtProp );
		}

		pclsObj->Release( );
	}

	// Libera recursos
	pSvc->Release( );
	pLoc->Release( );
	pEnumerator->Release( );
	CoUninitialize( );

	CachedDiskSerialNumber = StringCrypt::Get( ).EncryptString( serialNumber );

	if ( buffer != nullptr )
		*buffer = serialNumber;

	return true;
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

	// Remove quebras de linha e tabulações
	processed = std::regex_replace( processed , std::regex( xorstr_( "[\\r\\n]+" ) ) , " " );
	processed = std::regex_replace( processed , std::regex( xorstr_( "[\\t]+" ) ) , " " );

	// Remove múltiplos espaços em branco
	processed = std::regex_replace( processed , std::regex( xorstr_( " +" ) ) , " " );

	// Extrai os IDs de usuário
	std::vector<std::string> userIds;
	std::regex userIdRegex( "\"([0-9]+)\"\\s*\\{" );
	std::smatch matches;

	while ( std::regex_search( processed , matches , userIdRegex ) ) {
		userIds.push_back( matches[ 1 ] ); // Adiciona o ID ao vetor
		processed = matches.suffix( ).str( ); // Continua a buscar após o ID encontrado
	}

	// Constrói o JSON a partir dos IDs extraídos
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

	IP_ADAPTER_INFO AdapterInfo[ 16 ];              // Aloca informações para até 16 NICs
	DWORD dwBufLen = sizeof( AdapterInfo );         // Salva o tamanho da memória de AdapterInfo
	DWORD dwStatus = GetAdaptersInfo( AdapterInfo , &dwBufLen );
	if ( dwStatus != ERROR_SUCCESS ) {
		LogSystem::Get( ).ConsoleLog( _HWID , xorstr_( "GetAdaptersInfo failed with error:" ) , RED );
		return MACS;
	}

	PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;  // Ponteiro para a informação do adaptador atual
	char macAddr[ 18 ];

	while ( pAdapterInfo ) {
		// Formata o endereço MAC
		sprintf_s( macAddr , sizeof( macAddr ) , "%02X:%02X:%02X:%02X:%02X:%02X" ,
			pAdapterInfo->Address[ 0 ] , pAdapterInfo->Address[ 1 ] ,
			pAdapterInfo->Address[ 2 ] , pAdapterInfo->Address[ 3 ] ,
			pAdapterInfo->Address[ 4 ] , pAdapterInfo->Address[ 5 ] );

		// Retorna o endereço MAC do primeiro adaptador encontrado
		MACS.emplace_back( macAddr );
		pAdapterInfo = pAdapterInfo->Next;  // Move para o próximo adaptador
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
