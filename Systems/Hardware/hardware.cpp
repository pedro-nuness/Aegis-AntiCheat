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

// Bibliotecas adicionais (caso necessário)
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "comsuppw.lib")


#include "../Utils/xorstr.h"
#include "../Utils/utils.h"
#include "../../Systems/LogSystem/File/File.h"


#include <nlohmann/json.hpp>

using json = nlohmann::json;

bool hardware::GetMotherboardSerialNumber( std::string * buffer ) {
    HRESULT hres;

    // Inicializa o COM
    hres = CoInitializeEx( 0 , COINIT_MULTITHREADED );
    if ( FAILED( hres ) ) {
        Utils::Get( ).WarnMessage( _HWID , xorstr_( "Failed to initialize COM library" ) , RED );
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
        Utils::Get( ).WarnMessage( _HWID , xorstr_( "Failed to initialize security" ) , RED );
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
        Utils::Get( ).WarnMessage( _HWID , xorstr_( "Failed to create IWbemLocator object" ) , RED );
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
        Utils::Get( ).WarnMessage( _HWID , xorstr_( "Could not connect to WMI namespace" ) , RED );
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
        Utils::Get( ).WarnMessage( _HWID , xorstr_( "Could not set proxy blanket" ) , RED );
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
        Utils::Get( ).WarnMessage( _HWID , xorstr_( "Query for motherboard serial number failed" ) , RED );
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
    *buffer = serialNumber;
    return true;
}

bool hardware::GetDiskSerialNumber( std::string * buffer ) {
    HRESULT hres;

    // Inicializa o COM
    hres = CoInitializeEx( 0 , COINIT_MULTITHREADED );
    if ( FAILED( hres ) ) {
        Utils::Get( ).WarnMessage( _HWID , xorstr_( "Failed to initialize COM library" ) , RED );
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
        Utils::Get( ).WarnMessage( _HWID , xorstr_( "Failed to initialize security" ) , RED );
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
        Utils::Get( ).WarnMessage( _HWID , xorstr_( "Failed to create IWbemLocator object" ) , RED );
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
        Utils::Get( ).WarnMessage( _HWID , xorstr_( "Could not connect to WMI namespace" ) , RED );
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
        Utils::Get( ).WarnMessage( _HWID , xorstr_( "Could not set proxy blanket" ) , RED );
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
        Utils::Get( ).WarnMessage( _HWID , xorstr_( "Query for disk drive serial number failed" ) , RED );
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


bool hardware::GetLoggedUsers( std::vector<std::string> * Buffer ) {

    std::string SteamPath = checkRegistryForSteamPath( );
    if ( SteamPath.empty( ) ) {
        Utils::Get( ).WarnMessage( _CHECKER , xorstr_( "failed to get steam path" ) , RED );
        return false;
    }

    std::string LoginUsers = SteamPath + xorstr_( "\\config\\loginusers.vdf" );
    File LoginUsersFile( LoginUsers );
    if ( !LoginUsersFile.Exists( ) ) {
        Utils::Get( ).WarnMessage( _CHECKER , xorstr_( "can't find loginusers" ) , RED );
        return false;
    }

    // Load the JSON data from a file or string
    std::ifstream inputFile( LoginUsers ); // Assuming you saved the corrected JSON in this file
    json JS;

    if ( inputFile.is_open( ) ) {
        inputFile >> JS;
        inputFile.close( );
    }
    else {
        std::cerr << "Unable to open file." << std::endl;
        return false;
    }


    // Iterate through the users
    for ( auto & [id , user] : JS[ "users" ].items( ) ) {
        std::cout << "User ID: " << id << std::endl;
        std::cout << "Account Name: " << user[ "AccountName" ] << std::endl;
        std::cout << "Persona Name: " << user[ "PersonaName" ] << std::endl;
        std::cout << "Remember Password: " << user[ "RememberPassword" ] << std::endl;
        std::cout << "Wants Offline Mode: " << user[ "WantsOfflineMode" ] << std::endl;
        std::cout << "Skip Offline Mode Warning: " << user[ "SkipOfflineModeWarning" ] << std::endl;
        std::cout << "Allow Auto Login: " << user[ "AllowAutoLogin" ] << std::endl;
        std::cout << "Most Recent: " << user[ "MostRecent" ] << std::endl;
        std::cout << "Timestamp: " << user[ "Timestamp" ] << std::endl;
        std::cout << "-----------------------------------" << std::endl;   
    }

    return true;
}

std::vector<std::string> hardware::getMacAddress( ) {
	std::vector < std::string > MACS;

	IP_ADAPTER_INFO AdapterInfo[ 16 ];              // Aloca informações para até 16 NICs
	DWORD dwBufLen = sizeof( AdapterInfo );         // Salva o tamanho da memória de AdapterInfo
	DWORD dwStatus = GetAdaptersInfo( AdapterInfo , &dwBufLen );
	if ( dwStatus != ERROR_SUCCESS ) {
        Utils::Get( ).WarnMessage( _HWID , xorstr_( "GetAdaptersInfo failed with error:" ) , RED );
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

	return MACS;
}

std::string hardware::GetIp( int port ) {
    std::string Result = "";
    WSADATA wsaData;
    char hostname[ 256 ];
    struct addrinfo hints , * res = nullptr;

    // Initialize Winsock
    if ( WSAStartup( MAKEWORD( 2 , 2 ) , &wsaData ) != 0 ) {
        Utils::Get( ).WarnMessage( DARK_BLUE , xorstr_( "GetIp" ) , xorstr_( "WSAStartup failed" ) , RED );
        return Result;
    }

    // Get the hostname of the local machine
    if ( gethostname( hostname , sizeof( hostname ) ) == SOCKET_ERROR ) {
        Utils::Get( ).WarnMessage( DARK_BLUE , xorstr_( "GetIp" ) , xorstr_( "Error getting local hostname" ) , RED );
        WSACleanup( );
        return Result;
    }

    // Set up the hints for the type of address we're looking for
    memset( &hints , 0 , sizeof( hints ) );
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_STREAM;

    // Resolve the hostname to an IP address
    if ( getaddrinfo( hostname , NULL , &hints , &res ) != 0 ) {
        Utils::Get( ).WarnMessage( DARK_BLUE , xorstr_( "GetIp" ) , xorstr_( "Error getting local IP address" ) , RED );
        WSACleanup( );
        return Result;
    }

    // Extract the IP address from the result
    struct sockaddr_in * addr = ( struct sockaddr_in * ) res->ai_addr;
    char ip[ INET_ADDRSTRLEN ];

    // Use inet_ntoa instead of inet_ntop for better compatibility with Windows
    strcpy( ip , inet_ntoa( addr->sin_addr ) );

    // Return the extracted IP address as a string
    Result = std::string( ip );

    // Clean up
    freeaddrinfo( res );
    WSACleanup( );

    return Result;
}
