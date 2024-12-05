
#include <Windows.h>
#include <iostream>
#include <string>
#include "externals/minhook/MinHook.h"

std::string hKeyName( HKEY key ) {
	std::string hKeyName;

	// Mapeando o valor de hKey para o nome
	switch ( reinterpret_cast< std::uintptr_t >( key ) ) {
	case reinterpret_cast< std::uintptr_t >(HKEY_CLASSES_ROOT):
		hKeyName = "HKEY_CLASSES_ROOT";
		break;
	case  reinterpret_cast< std::uintptr_t >( HKEY_CURRENT_USER ):
		hKeyName = "HKEY_CURRENT_USER";
		break;
	case  reinterpret_cast< std::uintptr_t >( HKEY_LOCAL_MACHINE ):
		hKeyName = "HKEY_LOCAL_MACHINE";
		break;
	case  reinterpret_cast< std::uintptr_t >( HKEY_USERS ):
		hKeyName = "HKEY_USERS";
		break;
	case  reinterpret_cast< std::uintptr_t >( HKEY_CURRENT_CONFIG ):
		hKeyName = "HKEY_CURRENT_CONFIG";
		break;
	default:
		hKeyName = "Unknown HKEY";
		break;
	}
}

// Tipos das funções
typedef LSTATUS( WINAPI * RegCloseKey_t )( HKEY );
typedef LSTATUS( WINAPI * RegConnectRegistryA_t )( LPCSTR , HKEY , PHKEY );
typedef LSTATUS( WINAPI * RegConnectRegistryW_t )( LPCWSTR , HKEY , PHKEY );
typedef LSTATUS( WINAPI * RegCopyTreeA_t )( HKEY , LPCSTR , HKEY );
typedef LSTATUS( WINAPI * RegCopyTreeW_t )( HKEY , LPCWSTR , HKEY );
typedef LSTATUS( WINAPI * RegCreateKeyA_t )( HKEY , LPCSTR , PHKEY );
typedef LSTATUS( WINAPI * RegCreateKeyExA_t )( HKEY , LPCSTR , DWORD , LPSTR , DWORD , REGSAM , LPSECURITY_ATTRIBUTES , PHKEY , LPDWORD );
typedef LSTATUS( WINAPI * RegCreateKeyExW_t )( HKEY , LPCWSTR , DWORD , LPWSTR , DWORD , REGSAM , LPSECURITY_ATTRIBUTES , PHKEY , LPDWORD );
typedef LSTATUS( WINAPI * RegDeleteKeyA_t )( HKEY , LPCSTR );
typedef LSTATUS( WINAPI * RegDeleteKeyW_t )( HKEY , LPCWSTR );
typedef LSTATUS( WINAPI * RegDeleteValueA_t )( HKEY , LPCSTR );
typedef LSTATUS( WINAPI * RegDeleteValueW_t )( HKEY , LPCWSTR );
typedef LSTATUS( WINAPI * RegDisablePredefinedCache_t )( VOID );
typedef LSTATUS( WINAPI * RegDisablePredefinedCacheEx_t )( VOID );
typedef LSTATUS( WINAPI * RegDisableReflectionKey_t )( HKEY );
typedef LSTATUS( WINAPI * RegEnableReflectionKey_t )( HKEY );
typedef LSTATUS( WINAPI * RegEnumKeyA_t )( HKEY , DWORD , LPSTR , DWORD );
typedef LSTATUS( WINAPI * RegEnumKeyExA_t )( HKEY , DWORD , LPSTR , LPDWORD , LPDWORD , LPSTR , LPDWORD , PFILETIME );
typedef LSTATUS( WINAPI * RegEnumKeyExW_t )( HKEY , DWORD , LPWSTR , LPDWORD , LPDWORD , LPWSTR , LPDWORD , PFILETIME );
typedef LSTATUS( WINAPI * RegEnumKeyW_t )( HKEY , DWORD , LPWSTR , DWORD );
typedef LSTATUS( WINAPI * RegEnumValueA_t )( HKEY , DWORD , LPSTR , LPDWORD , LPDWORD , LPDWORD , LPBYTE , LPDWORD );
typedef LSTATUS( WINAPI * RegEnumValueW_t )( HKEY , DWORD , LPWSTR , LPDWORD , LPDWORD , LPDWORD , LPBYTE , LPDWORD );
typedef LSTATUS( WINAPI * RegFlushKey_t )( HKEY );
typedef LSTATUS( WINAPI * RegGetValueA_t )( HKEY , LPCSTR , LPCSTR , DWORD , LPDWORD , PVOID , LPDWORD );
typedef LSTATUS( WINAPI * RegGetValueW_t )( HKEY , LPCWSTR , LPCWSTR , DWORD , LPDWORD , PVOID , LPDWORD );
typedef LSTATUS( WINAPI * RegLoadAppKeyA_t )( LPCSTR , PHKEY , DWORD , REGSAM , LPSECURITY_ATTRIBUTES );
typedef LSTATUS( WINAPI * RegLoadAppKeyW_t )( LPCWSTR , PHKEY , DWORD , REGSAM , LPSECURITY_ATTRIBUTES );
typedef LSTATUS( WINAPI * RegLoadKeyA_t )( HKEY , LPCSTR , LPCSTR );
typedef LSTATUS( WINAPI * RegLoadKeyW_t )( HKEY , LPCWSTR , LPCWSTR );
typedef LSTATUS( WINAPI * RegLoadMUIStringA_t )( HKEY , LPCSTR , LPSTR , DWORD , LPDWORD , DWORD );
typedef LSTATUS( WINAPI * RegLoadMUIStringW_t )( HKEY , LPCWSTR , LPWSTR , DWORD , LPDWORD , DWORD );
typedef LSTATUS( WINAPI * RegNotifyChangeKeyValue_t )( HKEY , BOOL , DWORD , HANDLE , BOOL );
typedef LSTATUS( WINAPI * RegOpenCurrentUser_t )( DWORD , PHKEY );
typedef LSTATUS( WINAPI * RegOpenKeyA_t )( HKEY , LPCSTR , PHKEY );
typedef LSTATUS( WINAPI * RegOpenKeyExA_t )( HKEY , LPCSTR , DWORD , REGSAM , PHKEY );
typedef LSTATUS( WINAPI * RegOpenKeyExW_t )( HKEY , LPCWSTR , DWORD , REGSAM , PHKEY );
typedef LSTATUS( WINAPI * RegOpenKeyTransactedA_t )( HKEY , LPCSTR , DWORD , REGSAM , PHKEY , HANDLE , DWORD );
typedef LSTATUS( WINAPI * RegOpenKeyTransactedW_t )( HKEY , LPCWSTR , DWORD , REGSAM , PHKEY , HANDLE , DWORD );
typedef LSTATUS( WINAPI * RegOpenKeyW_t )( HKEY , LPCWSTR , PHKEY );
typedef LSTATUS( WINAPI * RegOpenUserClassesRoot_t )( DWORD , REGSAM , PHKEY );
typedef LSTATUS( WINAPI * RegOverridePredefKey_t )( HKEY , HKEY );
typedef LSTATUS( WINAPI * RegQueryInfoKeyA_t )( HKEY , LPSTR , LPDWORD , LPDWORD , LPDWORD , LPDWORD , LPDWORD , LPDWORD , LPDWORD , LPDWORD , LPDWORD , PFILETIME );
typedef LSTATUS( WINAPI * RegQueryInfoKeyW_t )( HKEY , LPWSTR , LPDWORD , LPDWORD , LPDWORD , LPDWORD , LPDWORD , LPDWORD , LPDWORD , LPDWORD , LPDWORD , PFILETIME );
typedef LSTATUS( WINAPI * RegQueryMultipleValuesA_t )( HKEY , PVALENT , DWORD , PSTR , LPDWORD );
typedef LSTATUS( WINAPI * RegQueryMultipleValuesW_t )( HKEY , PVALENT , DWORD , PWSTR , LPDWORD );
typedef LSTATUS( WINAPI * RegQueryReflectionKey_t )( HKEY , PBOOL );
typedef LSTATUS( WINAPI * RegQueryValueA_t )( HKEY , LPCSTR , LPSTR , LPDWORD );
typedef LSTATUS( WINAPI * RegQueryValueExA_t )( HKEY , LPCSTR , LPDWORD , LPDWORD , LPBYTE , LPDWORD );
typedef LSTATUS( WINAPI * RegQueryValueExW_t )( HKEY , LPCWSTR , LPDWORD , LPDWORD , LPBYTE , LPDWORD );
typedef LSTATUS( WINAPI * RegQueryValueW_t )( HKEY , LPCWSTR , LPWSTR , LPDWORD );
typedef LSTATUS( WINAPI * RegRenameKey_t )( HKEY , LPCWSTR , LPCWSTR );
typedef LSTATUS( WINAPI * RegReplaceKeyA_t )( LPCSTR , LPCSTR , LPCSTR );
typedef LSTATUS( WINAPI * RegReplaceKeyW_t )( LPCWSTR , LPCWSTR , LPCWSTR );
typedef LSTATUS( WINAPI * RegRestoreKeyA_t )( HKEY , LPCSTR , DWORD );
typedef LSTATUS( WINAPI * RegRestoreKeyW_t )( HKEY , LPCWSTR , DWORD );
typedef LSTATUS( WINAPI * RegSaveKeyA_t )( HKEY , LPCSTR , LPSECURITY_ATTRIBUTES );
typedef LSTATUS( WINAPI * RegSaveKeyExA_t )( HKEY , LPCSTR , LPSECURITY_ATTRIBUTES , DWORD );
typedef LSTATUS( WINAPI * RegSaveKeyExW_t )( HKEY , LPCWSTR , LPSECURITY_ATTRIBUTES , DWORD );
typedef LSTATUS( WINAPI * RegSaveKeyW_t )( HKEY , LPCWSTR , LPSECURITY_ATTRIBUTES );
typedef LSTATUS( WINAPI * RegSetKeyValueA_t )( HKEY , LPCSTR , LPCSTR , DWORD , CONST BYTE * , DWORD );
typedef LSTATUS( WINAPI * RegSetKeyValueW_t )( HKEY , LPCWSTR , LPCWSTR , DWORD , CONST BYTE * , DWORD );
typedef LSTATUS( WINAPI * RegSetValueA_t )( HKEY , LPCSTR , DWORD , LPCSTR , DWORD );
typedef LSTATUS( WINAPI * RegSetValueExA_t )( HKEY , LPCSTR , DWORD , DWORD , CONST BYTE * , DWORD );
typedef LSTATUS( WINAPI * RegSetValueExW_t )( HKEY , LPCWSTR , DWORD , DWORD , CONST BYTE * , DWORD );
typedef LSTATUS( WINAPI * RegSetValueW_t )( HKEY , LPCWSTR , DWORD , LPCWSTR , DWORD );
typedef LSTATUS( WINAPI * RegUnLoadKeyA_t )( HKEY , LPCSTR );
typedef LSTATUS( WINAPI * RegUnLoadKeyW_t )( HKEY , LPCWSTR );


RegCloseKey_t oRegCloseKey;
RegConnectRegistryA_t oRegConnectRegistryA;
RegConnectRegistryW_t oRegConnectRegistryW;
RegCopyTreeA_t oRegCopyTreeA;
RegCopyTreeW_t oRegCopyTreeW;
RegCreateKeyA_t oRegCreateKeyA;
RegCreateKeyExA_t oRegCreateKeyExA;
RegCreateKeyExW_t oRegCreateKeyExW;
RegDeleteKeyA_t oRegDeleteKeyA;
RegDeleteKeyW_t oRegDeleteKeyW;
RegDeleteValueA_t oRegDeleteValueA;
RegDeleteValueW_t oRegDeleteValueW;
RegDisablePredefinedCache_t oRegDisablePredefinedCache;
RegDisablePredefinedCacheEx_t oRegDisablePredefinedCacheEx;
RegDisableReflectionKey_t oRegDisableReflectionKey;
RegEnableReflectionKey_t oRegEnableReflectionKey;
RegEnumKeyA_t oRegEnumKeyA;
RegEnumKeyExA_t oRegEnumKeyExA;
RegEnumKeyExW_t oRegEnumKeyExW;
RegEnumKeyW_t oRegEnumKeyW;
RegEnumValueA_t oRegEnumValueA;
RegEnumValueW_t oRegEnumValueW;
RegFlushKey_t oRegFlushKey;
RegGetValueA_t oRegGetValueA;
RegGetValueW_t oRegGetValueW;
RegLoadAppKeyA_t oRegLoadAppKeyA;
RegLoadAppKeyW_t oRegLoadAppKeyW;
RegLoadKeyA_t oRegLoadKeyA;
RegLoadKeyW_t oRegLoadKeyW;
RegLoadMUIStringA_t oRegLoadMUIStringA;
RegLoadMUIStringW_t oRegLoadMUIStringW;
RegNotifyChangeKeyValue_t oRegNotifyChangeKeyValue;
RegOpenCurrentUser_t oRegOpenCurrentUser;
RegOpenKeyA_t oRegOpenKeyA;
RegOpenKeyExA_t oRegOpenKeyExA;
RegOpenKeyExW_t oRegOpenKeyExW;
RegOpenKeyTransactedA_t oRegOpenKeyTransactedA;
RegOpenKeyTransactedW_t oRegOpenKeyTransactedW;
RegOpenKeyW_t oRegOpenKeyW;
RegOpenUserClassesRoot_t oRegOpenUserClassesRoot;
RegOverridePredefKey_t oRegOverridePredefKey;
RegQueryInfoKeyA_t oRegQueryInfoKeyA;
RegQueryInfoKeyW_t oRegQueryInfoKeyW;
RegQueryMultipleValuesA_t oRegQueryMultipleValuesA;
RegQueryMultipleValuesW_t oRegQueryMultipleValuesW;
RegQueryReflectionKey_t oRegQueryReflectionKey;
RegQueryValueA_t oRegQueryValueA;
RegQueryValueExA_t oRegQueryValueExA;
RegQueryValueExW_t oRegQueryValueExW;
RegQueryValueW_t oRegQueryValueW;
RegRenameKey_t oRegRenameKey;
RegReplaceKeyA_t oRegReplaceKeyA;
RegReplaceKeyW_t oRegReplaceKeyW;
RegRestoreKeyA_t oRegRestoreKeyA;
RegRestoreKeyW_t oRegRestoreKeyW;
RegSaveKeyA_t oRegSaveKeyA;
RegSaveKeyExA_t oRegSaveKeyExA;
RegSaveKeyExW_t oRegSaveKeyExW;
RegSaveKeyW_t oRegSaveKeyW;
RegSetKeyValueA_t oRegSetKeyValueA;
RegSetKeyValueW_t oRegSetKeyValueW;
RegSetValueA_t oRegSetValueA;
RegSetValueExA_t oRegSetValueExA;
RegSetValueExW_t oRegSetValueExW;
RegSetValueW_t oRegSetValueW;
RegUnLoadKeyA_t oRegUnLoadKeyA;
RegUnLoadKeyW_t oRegUnLoadKeyW;

// Função Hook para RegCloseKey
LSTATUS WINAPI HookedRegCloseKey( HKEY hKey ) {
	std::cout << "[Hooked] RegCloseKey chamada." << std::endl;
	return oRegCloseKey( hKey );
}

// Função Hook para RegConnectRegistryA
LSTATUS WINAPI HookedRegConnectRegistryA( LPCSTR lpMachineName , HKEY hKey , PHKEY phkResult ) {
	std::cout << "[Hooked] RegConnectRegistryA chamada. MachineName: " << lpMachineName << std::endl;
	return oRegConnectRegistryA( lpMachineName , hKey , phkResult );
}

// Função Hook para RegConnectRegistryW
LSTATUS WINAPI HookedRegConnectRegistryW( LPCWSTR lpMachineName , HKEY hKey , PHKEY phkResult ) {
	std::wcout << "[Hooked] RegConnectRegistryW chamada. MachineName: " << lpMachineName << std::endl;
	return oRegConnectRegistryW( lpMachineName , hKey , phkResult );
}

// Função Hook para RegCreateKeyA
LSTATUS WINAPI HookedRegCreateKeyA( HKEY hKey , LPCSTR lpSubKey , PHKEY phkResult ) {
	std::cout << "[Hooked] RegCreateKeyA chamada. SubKey: " << lpSubKey << std::endl;
	return oRegCreateKeyA( hKey , lpSubKey , phkResult );
}

// Função Hook para RegCreateKeyExA
LSTATUS WINAPI HookedRegCreateKeyExA( HKEY hKey , LPCSTR lpSubKey , DWORD Reserved , LPSTR lpClass , DWORD dwOptions , REGSAM samDesired , LPSECURITY_ATTRIBUTES lpSecurityAttributes , PHKEY phkResult , LPDWORD lpdwDisposition ) {
	std::cout << "[Hooked] RegCreateKeyExA chamada. SubKey: " << lpSubKey << std::endl;
	return oRegCreateKeyExA( hKey , lpSubKey , Reserved , lpClass , dwOptions , samDesired , lpSecurityAttributes , phkResult , lpdwDisposition );
}

// Função Hook para RegCreateKeyExW
LSTATUS WINAPI HookedRegCreateKeyExW( HKEY hKey , LPCWSTR lpSubKey , DWORD Reserved , LPWSTR lpClass , DWORD dwOptions , REGSAM samDesired , LPSECURITY_ATTRIBUTES lpSecurityAttributes , PHKEY phkResult , LPDWORD lpdwDisposition ) {
	std::wcout << "[Hooked] RegCreateKeyExW chamada. SubKey: " << lpSubKey <<  std::endl;
	
	return ERROR_ACCESS_DENIED;

	return oRegCreateKeyExW( hKey , lpSubKey , Reserved , lpClass , dwOptions , samDesired , lpSecurityAttributes , phkResult , lpdwDisposition );
}

// Função Hook para RegDeleteKeyA
LSTATUS WINAPI HookedRegDeleteKeyA( HKEY hKey , LPCSTR lpSubKey ) {
	std::cout << "[Hooked] RegDeleteKeyA chamada. SubKey: " << lpSubKey << std::endl;
	return oRegDeleteKeyA( hKey , lpSubKey );
}

// Função Hook para RegDeleteKeyW
LSTATUS WINAPI HookedRegDeleteKeyW( HKEY hKey , LPCWSTR lpSubKey ) {
	std::wcout << "[Hooked] RegDeleteKeyW chamada. SubKey: " << lpSubKey << std::endl;
	return oRegDeleteKeyW( hKey , lpSubKey );
}

// Função Hook para RegDeleteValueA
LSTATUS WINAPI HookedRegDeleteValueA( HKEY hKey , LPCSTR lpValueName ) {
	std::cout << "[Hooked] RegDeleteValueA chamada. ValueName: " << lpValueName << std::endl;
	return oRegDeleteValueA( hKey , lpValueName );
}

// Função Hook para RegDeleteValueW
LSTATUS WINAPI HookedRegDeleteValueW( HKEY hKey , LPCWSTR lpValueName ) {
	std::wcout << "[Hooked] RegDeleteValueW chamada. ValueName: " << lpValueName << std::endl;
	return oRegDeleteValueW( hKey , lpValueName );
}

// Função Hook para RegEnableReflectionKey
LSTATUS WINAPI HookedRegEnableReflectionKey( HKEY hKey ) {
	std::cout << "[Hooked] RegEnableReflectionKey chamada." << std::endl;
	return oRegEnableReflectionKey( hKey );
}

// Função Hook para RegDisableReflectionKey
LSTATUS WINAPI HookedRegDisableReflectionKey( HKEY hKey ) {
	std::cout << "[Hooked] RegDisableReflectionKey chamada." << std::endl;
	return oRegDisableReflectionKey( hKey );
}

// Função Hook para RegEnumKeyExA
LSTATUS WINAPI HookedRegEnumKeyExA( HKEY hKey , DWORD dwIndex , LPSTR lpName , LPDWORD lpcchName , LPDWORD lpReserved , LPSTR lpClass , LPDWORD lpcchClass , PFILETIME lpftLastWriteTime ) {
	std::cout << "[Hooked] RegEnumKeyExA chamada. Index: " << dwIndex << std::endl;
	return oRegEnumKeyExA( hKey , dwIndex , lpName , lpcchName , lpReserved , lpClass , lpcchClass , lpftLastWriteTime );
}

// Função Hook para RegEnumKeyExW
LSTATUS WINAPI HookedRegEnumKeyExW( HKEY hKey , DWORD dwIndex , LPWSTR lpName , LPDWORD lpcchName , LPDWORD lpReserved , LPWSTR lpClass , LPDWORD lpcchClass , PFILETIME lpftLastWriteTime ) {
	std::wcout << "[Hooked] RegEnumKeyExW chamada. Index: " << dwIndex << std::endl;
	return oRegEnumKeyExW( hKey , dwIndex , lpName , lpcchName , lpReserved , lpClass , lpcchClass , lpftLastWriteTime );
}

// Função Hook para RegEnumValueA
LSTATUS WINAPI HookedRegEnumValueA( HKEY hKey , DWORD dwIndex , LPSTR lpValueName , LPDWORD lpcchValueName , LPDWORD lpReserved , LPDWORD lpType , LPBYTE lpData , LPDWORD lpcbData ) {
	std::cout << "[Hooked] RegEnumValueA chamada. Index: " << dwIndex << std::endl;
	return oRegEnumValueA( hKey , dwIndex , lpValueName , lpcchValueName , lpReserved , lpType , lpData , lpcbData );
}

// Função Hook para RegEnumValueW
LSTATUS WINAPI HookedRegEnumValueW( HKEY hKey , DWORD dwIndex , LPWSTR lpValueName , LPDWORD lpcchValueName , LPDWORD lpReserved , LPDWORD lpType , LPBYTE lpData , LPDWORD lpcbData ) {
	std::wcout << "[Hooked] RegEnumValueW chamada. Index: " << dwIndex << std::endl;
	return oRegEnumValueW( hKey , dwIndex , lpValueName , lpcchValueName , lpReserved , lpType , lpData , lpcbData );
}

// Função Hook para RegFlushKey
LSTATUS WINAPI HookedRegFlushKey( HKEY hKey ) {
	std::cout << "[Hooked] RegFlushKey chamada." << std::endl;
	return oRegFlushKey( hKey );
}

// Função Hook para RegGetValueA
LSTATUS WINAPI HookedRegGetValueA( HKEY hKey , LPCSTR lpSubKey , LPCSTR lpValue , DWORD dwFlags , LPDWORD pdwType , PVOID pvData , LPDWORD pcbData ) {
	std::cout << "[Hooked] RegGetValueA chamada. SubKey: " << lpSubKey << ", Value: " << lpValue << std::endl;
	return oRegGetValueA( hKey , lpSubKey , lpValue , dwFlags , pdwType , pvData , pcbData );
}

// Função Hook para RegGetValueW
LSTATUS WINAPI HookedRegGetValueW( HKEY hKey , LPCWSTR lpSubKey , LPCWSTR lpValue , DWORD dwFlags , LPDWORD pdwType , PVOID pvData , LPDWORD pcbData ) {
	std::wcout << "[Hooked] RegGetValueW chamada. SubKey: " << lpSubKey << ", Value: " << lpValue << std::endl;
	return oRegGetValueW( hKey , lpSubKey , lpValue , dwFlags , pdwType , pvData , pcbData );
}

// Função Hook para RegOpenKeyA
LSTATUS WINAPI HookedRegOpenKeyA( HKEY hKey , LPCSTR lpSubKey , PHKEY phkResult ) {
	std::cout << "[Hooked] RegOpenKeyA chamada. SubKey: " << lpSubKey << std::endl;
	return oRegOpenKeyA( hKey , lpSubKey , phkResult );
}

LSTATUS WINAPI HookedRegOpenKeyW( HKEY hKey , LPCWSTR lpSubKey , PHKEY phkResult ) {
	std::cout << "[Hooked] RegOpenKeyA chamada. SubKey: " << lpSubKey << std::endl;
	return oRegOpenKeyW( hKey , lpSubKey , phkResult );
}

// Função Hook para RegOpenKeyExA
LSTATUS WINAPI HookedRegOpenKeyExA( HKEY hKey , LPCSTR lpSubKey , DWORD ulOptions , REGSAM samDesired , PHKEY phkResult ) {
	std::cout << "[Hooked] RegOpenKeyExA chamada. SubKey: " << lpSubKey << std::endl;
	return oRegOpenKeyExA( hKey , lpSubKey , ulOptions , samDesired , phkResult );
}

// Função Hook para RegOpenKeyExW
LSTATUS WINAPI HookedRegOpenKeyExW( HKEY hKey , LPCWSTR lpSubKey , DWORD ulOptions , REGSAM samDesired , PHKEY phkResult ) {
	std::wcout << "[Hooked] RegOpenKeyExW chamada. SubKey: " << lpSubKey << std::endl;
	return oRegOpenKeyExW( hKey , lpSubKey , ulOptions , samDesired , phkResult );
}

// Função Hook para RegQueryInfoKeyA
LSTATUS WINAPI HookedRegQueryInfoKeyA( HKEY hKey , LPSTR lpClass , LPDWORD lpcbClass , LPDWORD lpReserved , LPDWORD lpcSubKeys , LPDWORD lpcbMaxSubKeyLen , LPDWORD lpcbMaxClassLen , LPDWORD lpcValues , LPDWORD lpcbMaxValueNameLen , LPDWORD lpcbMaxValueLen , LPDWORD lpcbSecurityDescriptor , PFILETIME lpftLastWriteTime ) {
	std::cout << "[Hooked] RegQueryInfoKeyA chamada." << std::endl;
	return oRegQueryInfoKeyA( hKey , lpClass , lpcbClass , lpReserved , lpcSubKeys , lpcbMaxSubKeyLen , lpcbMaxClassLen , lpcValues , lpcbMaxValueNameLen , lpcbMaxValueLen , lpcbSecurityDescriptor , lpftLastWriteTime );
}

// Função Hook para RegQueryInfoKeyW
LSTATUS WINAPI HookedRegQueryInfoKeyW( HKEY hKey , LPWSTR lpClass , LPDWORD lpcbClass , LPDWORD lpReserved , LPDWORD lpcSubKeys , LPDWORD lpcbMaxSubKeyLen , LPDWORD lpcbMaxClassLen , LPDWORD lpcValues , LPDWORD lpcbMaxValueNameLen , LPDWORD lpcbMaxValueLen , LPDWORD lpcbSecurityDescriptor , PFILETIME lpftLastWriteTime ) {
	std::wcout << "[Hooked] RegQueryInfoKeyW chamada." << std::endl;
	return oRegQueryInfoKeyW( hKey , lpClass , lpcbClass , lpReserved , lpcSubKeys , lpcbMaxSubKeyLen , lpcbMaxClassLen , lpcValues , lpcbMaxValueNameLen , lpcbMaxValueLen , lpcbSecurityDescriptor , lpftLastWriteTime );
}


// Função Hook para RegEnumKeyA
LSTATUS WINAPI HookedRegEnumKeyA( HKEY hKey , DWORD dwIndex , LPSTR lpName , DWORD dwSize ) {
	std::cout << "[Hooked] RegEnumKeyA chamada. Index: " << dwIndex << std::endl;
	return oRegEnumKeyA( hKey , dwIndex , lpName , dwSize );
}


LSTATUS WINAPI HookedRegEnumKeyW( HKEY hKey , DWORD dwIndex , LPWSTR lpName , DWORD dwSize ) {
	std::cout << "[Hooked] RegEnumKeyA chamada. Index: " << dwIndex << std::endl;
	return oRegEnumKeyW( hKey , dwIndex , lpName , dwSize );
}



// Função Hook para RegSetValueA
LSTATUS WINAPI HookedRegSetValueA( HKEY hKey , LPCSTR lpSubKey , DWORD dwType , LPCSTR lpData , DWORD dwSize ) {
	std::cout << "[Hooked] RegSetValueA chamada. SubKey: " << lpSubKey << std::endl;
	return oRegSetValueA( hKey , lpSubKey , dwType , lpData , dwSize );
}

// Função Hook para RegSetValueExA
LSTATUS WINAPI HookedRegSetValueExA( HKEY hKey , LPCSTR lpValueName , DWORD Reserved , DWORD dwType , CONST BYTE * lpData , DWORD dwSize ) {
	std::cout << "[Hooked] RegSetValueExA chamada. ValueName: " << lpValueName << std::endl;
	return oRegSetValueExA( hKey , lpValueName , Reserved , dwType , lpData , dwSize );
}

// Função Hook para RegSetValueExW
LSTATUS WINAPI HookedRegSetValueExW( HKEY hKey , LPCWSTR lpValueName , DWORD Reserved , DWORD dwType , CONST BYTE * lpData , DWORD dwSize ) {
	std::wcout << "[Hooked] RegSetValueExW chamada. ValueName: " << lpValueName << std::endl;
	return oRegSetValueExW( hKey , lpValueName , Reserved , dwType , lpData , dwSize );
}

// Função Hook para RegUnLoadKeyA
LSTATUS WINAPI HookedRegUnLoadKeyA( HKEY hKey , LPCSTR lpSubKey ) {
	std::cout << "[Hooked] RegUnLoadKeyA chamada. SubKey: " << lpSubKey << std::endl;
	return oRegUnLoadKeyA( hKey , lpSubKey );
}

// Função Hook para RegUnLoadKeyW
LSTATUS WINAPI HookedRegUnLoadKeyW( HKEY hKey , LPCWSTR lpSubKey ) {
	std::wcout << "[Hooked] RegUnLoadKeyW chamada. SubKey: " << lpSubKey << std::endl;
	return oRegUnLoadKeyW( hKey , lpSubKey );
}


// Função Hook para RegCopyTreeA
LSTATUS WINAPI HookedRegCopyTreeA( HKEY hKeySrc , LPCSTR lpSubKeySrc , HKEY hKeyDest ) {
	std::cout << "[Hooked] RegCopyTreeA chamada. SubKey: " << lpSubKeySrc << std::endl;
	return oRegCopyTreeA( hKeySrc , lpSubKeySrc , hKeyDest );  // Chama a função original
}

// Função Hook para RegCopyTreeW
LSTATUS WINAPI HookedRegCopyTreeW( HKEY hKeySrc , LPCWSTR lpSubKeySrc , HKEY hKeyDest ) {
	std::wcout << "[Hooked] RegCopyTreeW chamada. SubKey: " << lpSubKeySrc << std::endl;
	return oRegCopyTreeW( hKeySrc , lpSubKeySrc , hKeyDest );  // Chama a função original
}

// Função Hook para RegLoadKeyA
LSTATUS WINAPI HookedRegLoadKeyA( HKEY hKey , LPCSTR lpSubKey , LPCSTR lpFile ) {
	std::cout << "[Hooked] RegLoadKeyA chamada. SubKey: " << lpSubKey << " Arquivo: " << lpFile << std::endl;
	return oRegLoadKeyA( hKey , lpSubKey , lpFile );  // Chama a função original
}

// Função Hook para RegLoadKeyW
LSTATUS WINAPI HookedRegLoadKeyW( HKEY hKey , LPCWSTR lpSubKey , LPCWSTR lpFile ) {
	std::wcout << "[Hooked] RegLoadKeyW chamada. SubKey: " << lpSubKey << " Arquivo: " << lpFile << std::endl;
	return oRegLoadKeyW( hKey , lpSubKey , lpFile );  // Chama a função original
}





bool CreateRegHooks( ) {

	// Criação dos hooks
	if ( MH_CreateHook( &RegCloseKey , &HookedRegCloseKey , reinterpret_cast< LPVOID * >( &oRegCloseKey ) ) != MH_OK ||
		MH_CreateHook( &RegConnectRegistryA , &HookedRegConnectRegistryA , reinterpret_cast< LPVOID * >( &oRegConnectRegistryA ) ) != MH_OK ||
		MH_CreateHook( &RegConnectRegistryW , &HookedRegConnectRegistryW , reinterpret_cast< LPVOID * >( &oRegConnectRegistryW ) ) != MH_OK ||
		MH_CreateHook( &RegCopyTreeA , &HookedRegCopyTreeA , reinterpret_cast< LPVOID * >( &oRegCopyTreeA ) ) != MH_OK ||
		MH_CreateHook( &RegCopyTreeW , &HookedRegCopyTreeW , reinterpret_cast< LPVOID * >( &oRegCopyTreeW ) ) != MH_OK ||
		MH_CreateHook( &RegCreateKeyA , &HookedRegCreateKeyA , reinterpret_cast< LPVOID * >( &oRegCreateKeyA ) ) != MH_OK ||
		MH_CreateHook( &RegCreateKeyExA , &HookedRegCreateKeyExA , reinterpret_cast< LPVOID * >( &oRegCreateKeyExA ) ) != MH_OK ||
		MH_CreateHook( &RegCreateKeyExW , &HookedRegCreateKeyExW , reinterpret_cast< LPVOID * >( &oRegCreateKeyExW ) ) != MH_OK ||
		MH_CreateHook( &RegDeleteKeyA , &HookedRegDeleteKeyA , reinterpret_cast< LPVOID * >( &oRegDeleteKeyA ) ) != MH_OK ||
		MH_CreateHook( &RegDeleteKeyW , &HookedRegDeleteKeyW , reinterpret_cast< LPVOID * >( &oRegDeleteKeyW ) ) != MH_OK ||
		MH_CreateHook( &RegDeleteValueA , &HookedRegDeleteValueA , reinterpret_cast< LPVOID * >( &oRegDeleteValueA ) ) != MH_OK ||
		MH_CreateHook( &RegDeleteValueW , &HookedRegDeleteValueW , reinterpret_cast< LPVOID * >( &oRegDeleteValueW ) ) != MH_OK ||
	/*	MH_CreateHook( &RegDisablePredefinedCache , &HookedRegDisablePredefinedCache , reinterpret_cast< LPVOID * >( &oRegDisablePredefinedCache ) ) != MH_OK ||
		MH_CreateHook( &RegDisablePredefinedCacheEx , &HookedRegDisablePredefinedCacheEx , reinterpret_cast< LPVOID * >( &oRegDisablePredefinedCacheEx ) ) != MH_OK ||*/
		MH_CreateHook( &RegDisableReflectionKey , &HookedRegDisableReflectionKey , reinterpret_cast< LPVOID * >( &oRegDisableReflectionKey ) ) != MH_OK ||
		MH_CreateHook( &RegEnableReflectionKey , &HookedRegEnableReflectionKey , reinterpret_cast< LPVOID * >( &oRegEnableReflectionKey ) ) != MH_OK ||
		MH_CreateHook( &RegEnumKeyA , &HookedRegEnumKeyA , reinterpret_cast< LPVOID * >( &oRegEnumKeyA ) ) != MH_OK ||
		MH_CreateHook( &RegEnumKeyExA , &HookedRegEnumKeyExA , reinterpret_cast< LPVOID * >( &oRegEnumKeyExA ) ) != MH_OK ||
		MH_CreateHook( &RegEnumKeyExW , &HookedRegEnumKeyExW , reinterpret_cast< LPVOID * >( &oRegEnumKeyExW ) ) != MH_OK ||
		MH_CreateHook( &RegEnumKeyW , &HookedRegEnumKeyW , reinterpret_cast< LPVOID * >( &oRegEnumKeyW ) ) != MH_OK ||
		MH_CreateHook( &RegEnumValueA , &HookedRegEnumValueA , reinterpret_cast< LPVOID * >( &oRegEnumValueA ) ) != MH_OK ||
		MH_CreateHook( &RegEnumValueW , &HookedRegEnumValueW , reinterpret_cast< LPVOID * >( &oRegEnumValueW ) ) != MH_OK ||
		MH_CreateHook( &RegFlushKey , &HookedRegFlushKey , reinterpret_cast< LPVOID * >( &oRegFlushKey ) ) != MH_OK ||
		MH_CreateHook( &RegGetValueA , &HookedRegGetValueA , reinterpret_cast< LPVOID * >( &oRegGetValueA ) ) != MH_OK ||
		MH_CreateHook( &RegGetValueW , &HookedRegGetValueW , reinterpret_cast< LPVOID * >( &oRegGetValueW ) ) != MH_OK ||
		//MH_CreateHook( &RegLoadAppKeyA , &HookedRegLoadAppKeyA , reinterpret_cast< LPVOID * >( &oRegLoadAppKeyA ) ) != MH_OK ||
		//MH_CreateHook( &RegLoadAppKeyW , &HookedRegLoadAppKeyW , reinterpret_cast< LPVOID * >( &oRegLoadAppKeyW ) ) != MH_OK ||
		MH_CreateHook( &RegLoadKeyA , &HookedRegLoadKeyA , reinterpret_cast< LPVOID * >( &oRegLoadKeyA ) ) != MH_OK ||
		MH_CreateHook( &RegLoadKeyW , &HookedRegLoadKeyW , reinterpret_cast< LPVOID * >( &oRegLoadKeyW ) ) != MH_OK ||
		//MH_CreateHook( &RegLoadMUIStringA , &HookedRegLoadMUIStringA , reinterpret_cast< LPVOID * >( &oRegLoadMUIStringA ) ) != MH_OK ||
		//MH_CreateHook( &RegLoadMUIStringW , &HookedRegLoadMUIStringW , reinterpret_cast< LPVOID * >( &oRegLoadMUIStringW ) ) != MH_OK ||
		//MH_CreateHook( &RegNotifyChangeKeyValue , &HookedRegNotifyChangeKeyValue , reinterpret_cast< LPVOID * >( &oRegNotifyChangeKeyValue ) ) != MH_OK ||
		//MH_CreateHook( &RegOpenCurrentUser , &HookedRegOpenCurrentUser , reinterpret_cast< LPVOID * >( &oRegOpenCurrentUser ) ) != MH_OK ||
		MH_CreateHook( &RegOpenKeyA , &HookedRegOpenKeyA , reinterpret_cast< LPVOID * >( &oRegOpenKeyA ) ) != MH_OK ||
		MH_CreateHook( &RegOpenKeyExA , &HookedRegOpenKeyExA , reinterpret_cast< LPVOID * >( &oRegOpenKeyExA ) ) != MH_OK ||
		MH_CreateHook( &RegOpenKeyExW , &HookedRegOpenKeyExW , reinterpret_cast< LPVOID * >( &oRegOpenKeyExW ) ) != MH_OK ||
		//MH_CreateHook( &RegOpenKeyTransactedA , &HookedRegOpenKeyTransactedA , reinterpret_cast< LPVOID * >( &oRegOpenKeyTransactedA ) ) != MH_OK ||
		//MH_CreateHook( &RegOpenKeyTransactedW , &HookedRegOpenKeyTransactedW , reinterpret_cast< LPVOID * >( &oRegOpenKeyTransactedW ) ) != MH_OK ||
		MH_CreateHook( &RegOpenKeyW , &HookedRegOpenKeyW , reinterpret_cast< LPVOID * >( &oRegOpenKeyW ) ) != MH_OK ||
		//MH_CreateHook( &RegOpenUserClassesRoot , &HookedRegOpenUserClassesRoot , reinterpret_cast< LPVOID * >( &oRegOpenUserClassesRoot ) ) != MH_OK ||
		//MH_CreateHook( &RegOverridePredefKey , &HookedRegOverridePredefKey , reinterpret_cast< LPVOID * >( &oRegOverridePredefKey ) ) != MH_OK ||
		MH_CreateHook( &RegQueryInfoKeyA , &HookedRegQueryInfoKeyA , reinterpret_cast< LPVOID * >( &oRegQueryInfoKeyA ) ) != MH_OK ||
		MH_CreateHook( &RegQueryInfoKeyW , &HookedRegQueryInfoKeyW , reinterpret_cast< LPVOID * >( &oRegQueryInfoKeyW ) ) != MH_OK ||
	/*	MH_CreateHook( &RegQueryMultipleValuesA , &HookedRegQueryMultipleValuesA , reinterpret_cast< LPVOID * >( &oRegQueryMultipleValuesA ) ) != MH_OK ||
		MH_CreateHook( &RegQueryMultipleValuesW , &HookedRegQueryMultipleValuesW , reinterpret_cast< LPVOID * >( &oRegQueryMultipleValuesW ) ) != MH_OK ||
		MH_CreateHook( &RegQueryReflectionKey , &HookedRegQueryReflectionKey , reinterpret_cast< LPVOID * >( &oRegQueryReflectionKey ) ) != MH_OK ||
		MH_CreateHook( &RegQueryValueA , &HookedRegQueryValueA , reinterpret_cast< LPVOID * >( &oRegQueryValueA ) ) != MH_OK ||
		MH_CreateHook( &RegQueryValueExA , &HookedRegQueryValueExA , reinterpret_cast< LPVOID * >( &oRegQueryValueExA ) ) != MH_OK ||
		MH_CreateHook( &RegQueryValueExW , &HookedRegQueryValueExW , reinterpret_cast< LPVOID * >( &oRegQueryValueExW ) ) != MH_OK ||
		MH_CreateHook( &RegQueryValueW , &HookedRegQueryValueW , reinterpret_cast< LPVOID * >( &oRegQueryValueW ) ) != MH_OK ||
		MH_CreateHook( &RegRenameKey , &HookedRegRenameKey , reinterpret_cast< LPVOID * >( &oRegRenameKey ) ) != MH_OK ||
		MH_CreateHook( &RegReplaceKeyA , &HookedRegReplaceKeyA , reinterpret_cast< LPVOID * >( &oRegReplaceKeyA ) ) != MH_OK ||
		MH_CreateHook( &RegReplaceKeyW , &HookedRegReplaceKeyW , reinterpret_cast< LPVOID * >( &oRegReplaceKeyW ) ) != MH_OK ||
		MH_CreateHook( &RegRestoreKeyA , &HookedRegRestoreKeyA , reinterpret_cast< LPVOID * >( &oRegRestoreKeyA ) ) != MH_OK ||
		MH_CreateHook( &RegRestoreKeyW , &HookedRegRestoreKeyW , reinterpret_cast< LPVOID * >( &oRegRestoreKeyW ) ) != MH_OK ||
		MH_CreateHook( &RegSaveKeyA , &HookedRegSaveKeyA , reinterpret_cast< LPVOID * >( &oRegSaveKeyA ) ) != MH_OK ||
		MH_CreateHook( &RegSaveKeyExA , &HookedRegSaveKeyExA , reinterpret_cast< LPVOID * >( &oRegSaveKeyExA ) ) != MH_OK ||
		MH_CreateHook( &RegSaveKeyExW , &HookedRegSaveKeyExW , reinterpret_cast< LPVOID * >( &oRegSaveKeyExW ) ) != MH_OK ||
		MH_CreateHook( &RegSaveKeyW , &HookedRegSaveKeyW , reinterpret_cast< LPVOID * >( &oRegSaveKeyW ) ) != MH_OK ||
		MH_CreateHook( &RegSetKeySecurity , &HookedRegSetKeySecurity , reinterpret_cast< LPVOID * >( &oRegSetKeySecurity ) ) != MH_OK ||*/
		MH_CreateHook( &RegSetValueA , &HookedRegSetValueA , reinterpret_cast< LPVOID * >( &oRegSetValueA ) ) != MH_OK ||
		MH_CreateHook( &RegSetValueExA , &HookedRegSetValueExA , reinterpret_cast< LPVOID * >( &oRegSetValueExA ) ) != MH_OK ||
		MH_CreateHook( &RegSetValueExW , &HookedRegSetValueExW , reinterpret_cast< LPVOID * >( &oRegSetValueExW ) ) != MH_OK ||
		//MH_CreateHook( &RegSetValueW , &HookedRegSetValueW , reinterpret_cast< LPVOID * >( &oRegSetValueW ) ) != MH_OK ||
		//MH_CreateHook( &RegUnloadKey , &HookedRegUnloadKey , reinterpret_cast< LPVOID * >( &oRegUnloadKey ) ) != MH_OK ||
		MH_CreateHook( &RegUnLoadKeyA , &HookedRegUnLoadKeyA , reinterpret_cast< LPVOID * >( &oRegUnLoadKeyA ) ) != MH_OK ||
		MH_CreateHook( &RegUnLoadKeyW , &HookedRegUnLoadKeyW , reinterpret_cast< LPVOID * >( &oRegUnLoadKeyW ) ) != MH_OK ) {
		std::cerr << "Erro ao criar hook!" << std::endl;
		return FALSE;
	}

	return TRUE;
}
