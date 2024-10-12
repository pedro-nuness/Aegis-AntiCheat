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

std::string hardware::GetMotherboardSerialNumber( ) {
	HRESULT hres;

	// Inicializa o COM
	hres = CoInitializeEx( 0 , COINIT_MULTITHREADED );
	if ( FAILED( hres ) ) {
		return xorstr_("Failed to initialize COM library");
	}

	// Define os níveis de segurança do COM
	hres = CoInitializeSecurity(
		nullptr , -1 , nullptr , nullptr ,
		RPC_C_AUTHN_LEVEL_DEFAULT ,
		RPC_C_IMP_LEVEL_IMPERSONATE ,
		nullptr , EOAC_NONE , nullptr );

	if ( FAILED( hres ) ) {
		CoUninitialize( );
		return  xorstr_( "Failed to initialize security" );
	}

	// Obtém o ponteiro para o serviço WMI
	IWbemLocator * pLoc = nullptr;

	hres = CoCreateInstance(
		CLSID_WbemLocator , 0 ,
		CLSCTX_INPROC_SERVER ,
		IID_IWbemLocator , ( LPVOID * ) &pLoc );

	if ( FAILED( hres ) ) {
		CoUninitialize( );
		return  xorstr_( "Failed to create IWbemLocator object" );
	}

	IWbemServices * pSvc = nullptr;

	// Conecta-se ao namespace root\cimv2
	hres = pLoc->ConnectServer(
		_bstr_t( L"ROOT\\CIMV2" ) , nullptr , nullptr , 0 ,
		NULL , 0 , 0 , &pSvc );

	if ( FAILED( hres ) ) {
		pLoc->Release( );
		CoUninitialize( );
		return  xorstr_( "Could not connect to WMI namespace" );
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
		return xorstr_( "Could not set proxy blanket" );
	}

	// Faz a consulta WMI
	IEnumWbemClassObject * pEnumerator = nullptr;
	hres = pSvc->ExecQuery(
		bstr_t( xorstr_("WQL" ) ) ,
		bstr_t( xorstr_("SELECT SerialNumber FROM Win32_BaseBoard" ) ) ,
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY ,
		nullptr ,
		&pEnumerator );

	if ( FAILED( hres ) ) {
		pSvc->Release( );
		pLoc->Release( );
		CoUninitialize( );
		return  xorstr_( "Query for motherboard serial number failed" );
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

	return serialNumber;
}

std::string hardware::GetDiskSerialNumber( ) {
	HRESULT hres;

	// Inicializa o COM
	hres = CoInitializeEx( 0 , COINIT_MULTITHREADED );
	if ( FAILED( hres ) ) {
		return xorstr_("Failed to initialize COM library");
	}

	// Define os níveis de segurança do COM
	hres = CoInitializeSecurity(
		nullptr , -1 , nullptr , nullptr ,
		RPC_C_AUTHN_LEVEL_DEFAULT ,
		RPC_C_IMP_LEVEL_IMPERSONATE ,
		nullptr , EOAC_NONE , nullptr );

	if ( FAILED( hres ) ) {
		CoUninitialize( );
		return  xorstr_( "Failed to initialize security" );
	}

	// Obtém o ponteiro para o serviço WMI
	IWbemLocator * pLoc = nullptr;

	hres = CoCreateInstance(
		CLSID_WbemLocator , 0 ,
		CLSCTX_INPROC_SERVER ,
		IID_IWbemLocator , ( LPVOID * ) &pLoc );

	if ( FAILED( hres ) ) {
		CoUninitialize( );
		return  xorstr_( "Failed to create IWbemLocator object" );
	}

	IWbemServices * pSvc = nullptr;

	// Conecta-se ao namespace root\cimv2
	hres = pLoc->ConnectServer(
		_bstr_t( L"ROOT\\CIMV2" ) , nullptr , nullptr , 0 ,
		NULL , 0 , 0 , &pSvc );

	if ( FAILED( hres ) ) {
		pLoc->Release( );
		CoUninitialize( );
		return xorstr_( "Could not connect to WMI namespace" );
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
		return  xorstr_( "Could not set proxy blanket" );
	}

	// Faz a consulta WMI
	IEnumWbemClassObject * pEnumerator = nullptr;
	hres = pSvc->ExecQuery(
		bstr_t( xorstr_( "WQL" ) ) ,
		bstr_t( xorstr_( "SELECT SerialNumber FROM Win32_DiskDrive" )) ,
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY ,
		nullptr ,
		&pEnumerator );

	if ( FAILED( hres ) ) {
		pSvc->Release( );
		pLoc->Release( );
		CoUninitialize( );
		return  xorstr_( "Query for disk drive serial number failed");
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

	return serialNumber;
}


std::vector<std::string> hardware::getMacAddress( ) {
	std::vector < std::string > MACS;

	IP_ADAPTER_INFO AdapterInfo[ 16 ];              // Aloca informações para até 16 NICs
	DWORD dwBufLen = sizeof( AdapterInfo );         // Salva o tamanho da memória de AdapterInfo
	DWORD dwStatus = GetAdaptersInfo( AdapterInfo , &dwBufLen );
	if ( dwStatus != ERROR_SUCCESS ) {
		std::cerr << xorstr_("GetAdaptersInfo failed with error: ") << dwStatus << std::endl;
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
		std::cerr << "WSAStartup failed.\n";
		return Result;
	}

	// Get the hostname of the local machine
	if ( gethostname( hostname , sizeof( hostname ) ) == SOCKET_ERROR ) {
		std::cerr << "Error getting local hostname.\n";
		WSACleanup( );
		return Result;
	}

	// Set up the hints for the type of address we're looking for
	memset( &hints , 0 , sizeof( hints ) );
	hints.ai_family = AF_INET; // IPv4
	hints.ai_socktype = SOCK_STREAM;

	// Resolve the hostname to an IP address
	if ( getaddrinfo( hostname , NULL , &hints , &res ) != 0 ) {
		std::cerr << "Error getting local IP address.\n";
		WSACleanup( );
		return Result;
	}

	// Extract the IP address from the result
	struct sockaddr_in * addr = ( struct sockaddr_in * ) res->ai_addr;
	char ip[ INET_ADDRSTRLEN ];

	// Use inet_ntoa instead of inet_ntop for better compatibility with Windows
	strcpy( ip , inet_ntoa( addr->sin_addr ) );

	std::cout << "Local IP Address: " << ip << std::endl;

	// Return the extracted IP address as a string
	Result = std::string( ip );

	// Clean up
	freeaddrinfo( res );
	WSACleanup( );

	return Result;
}
