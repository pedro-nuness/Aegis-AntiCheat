#include "Authentication.h"
#include <tchar.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <mscat.h>

#include <iostream>
#include <string>

#include "../Utils/utils.h"
#include "../Utils/xorstr.h"

#pragma comment(lib, "wintrust.lib")

BOOL Authentication::VerifyEmbeddedSignature( std::string filePath )
{

	std::wstring wStrFilePath = std::wstring( filePath.begin( ) , filePath.end( ) );

	WINTRUST_FILE_INFO fileInfo = { 0 };
	fileInfo.cbStruct = sizeof( WINTRUST_FILE_INFO );
	fileInfo.pcwszFilePath = wStrFilePath.c_str( );
	fileInfo.hFile = NULL;
	fileInfo.pgKnownSubject = NULL;

	GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

	WINTRUST_DATA trustData = { 0 };
	trustData.cbStruct = sizeof( trustData );
	trustData.pPolicyCallbackData = NULL;
	trustData.pSIPClientData = NULL;
	trustData.dwUIChoice = WTD_UI_NONE;
	trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
	trustData.dwUnionChoice = WTD_CHOICE_FILE;
	trustData.dwStateAction = WTD_STATEACTION_VERIFY;
	trustData.hWVTStateData = NULL;
	trustData.pwszURLReference = NULL;
	trustData.dwUIContext = 0;
	trustData.pFile = &fileInfo;

	LONG status = WinVerifyTrust( NULL , &policyGUID , &trustData );

	trustData.dwStateAction = WTD_STATEACTION_CLOSE;
	WinVerifyTrust( NULL , &policyGUID , &trustData );

	// Utils::Get( ).WarnMessage( _DETECTION , filePath + xorstr_( "file verification returned: " ) + std::to_string( status ) , YELLOW );

	return status == ERROR_SUCCESS;
}

BOOL Authentication::VerifyCatalogSignature( std::string filePath ) {
	HANDLE hFile = CreateFile( filePath.c_str( ) , GENERIC_READ , FILE_SHARE_READ , NULL , OPEN_EXISTING , FILE_ATTRIBUTE_NORMAL , NULL );
	if ( hFile == INVALID_HANDLE_VALUE ) {
		// std::wcerr << L"Could not open file: " << filePath << std::endl;
		return false;
	}

	HCATADMIN hCatAdmin = NULL;
	if ( !CryptCATAdminAcquireContext( &hCatAdmin , NULL , 0 ) ) {
		CloseHandle( hFile );
		return false;
	}

	BYTE pbHash[ 100 ];
	DWORD cbHash = sizeof( pbHash );
	if ( !CryptCATAdminCalcHashFromFileHandle( hFile , &cbHash , pbHash , 0 ) ) {
		CryptCATAdminReleaseContext( hCatAdmin , 0 );
		CloseHandle( hFile );
		return false;
	}

	CATALOG_INFO CatInfo;
	memset( &CatInfo , 0 , sizeof( CATALOG_INFO ) );
	CatInfo.cbStruct = sizeof( CATALOG_INFO );

	HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash( hCatAdmin , pbHash , cbHash , 0 , NULL );
	if ( hCatInfo == NULL ) {
		//std::wcerr << L"No catalog file found for " << filePath << std::endl;
		CryptCATAdminReleaseContext( hCatAdmin , 0 );
		CloseHandle( hFile );
		return false;
	}

	if ( !CryptCATCatalogInfoFromContext( hCatInfo , &CatInfo , 0 ) ) {
		CryptCATAdminReleaseCatalogContext( hCatAdmin , hCatInfo , 0 );
		CryptCATAdminReleaseContext( hCatAdmin , 0 );
		CloseHandle( hFile );
		return false;
	}

	WINTRUST_CATALOG_INFO WinTrustCatalogInfo;
	memset( &WinTrustCatalogInfo , 0 , sizeof( WinTrustCatalogInfo ) );
	WinTrustCatalogInfo.cbStruct = sizeof( WINTRUST_CATALOG_INFO );
	WinTrustCatalogInfo.pcwszCatalogFilePath = CatInfo.wszCatalogFile;
	WinTrustCatalogInfo.pcwszMemberTag = NULL;

	wchar_t wideProcessImagePath[ MAX_PATH ];
	// Converte de multibyte (char) para wide char (wchar_t)
	MultiByteToWideChar( CP_ACP , 0 , filePath.c_str( ) , -1 , wideProcessImagePath , MAX_PATH );

	WinTrustCatalogInfo.pcwszMemberFilePath = wideProcessImagePath;
	WinTrustCatalogInfo.hMemberFile = hFile;
	WinTrustCatalogInfo.pbCalculatedFileHash = pbHash;
	WinTrustCatalogInfo.cbCalculatedFileHash = cbHash;

	GUID ActionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	WINTRUST_DATA WinTrustData;
	memset( &WinTrustData , 0 , sizeof( WinTrustData ) );
	WinTrustData.cbStruct = sizeof( WINTRUST_DATA );
	WinTrustData.pPolicyCallbackData = NULL;
	WinTrustData.pSIPClientData = NULL;
	WinTrustData.dwUIChoice = WTD_UI_NONE;
	WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
	WinTrustData.dwUnionChoice = WTD_CHOICE_CATALOG;
	WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
	WinTrustData.hWVTStateData = NULL;
	WinTrustData.pwszURLReference = NULL;
	WinTrustData.dwProvFlags = WTD_REVOCATION_CHECK_NONE;
	WinTrustData.dwUIContext = 0;
	WinTrustData.pCatalog = &WinTrustCatalogInfo;

	LONG lStatus = WinVerifyTrust( NULL , &ActionGuid , &WinTrustData );

	WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
	WinVerifyTrust( NULL , &ActionGuid , &WinTrustData );

	CryptCATAdminReleaseCatalogContext( hCatAdmin , hCatInfo , 0 );
	CryptCATAdminReleaseContext( hCatAdmin , 0 );
	CloseHandle( hFile );

	return lStatus == ERROR_SUCCESS;
}

/// <summary>
/// Takes in a file path and returns if module is signed of not
/// </summary>
/// <param name="filePath:">Full file path to DLL</param>
/// <returns>True if file has a signature</returns>
BOOL Authentication::HasSignature( std::string filePath )
{
	return ( Authentication::VerifyEmbeddedSignature( filePath ) ||
		Authentication::VerifyCatalogSignature( filePath ) );
}