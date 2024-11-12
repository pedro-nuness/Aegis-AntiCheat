#include "Preventions.h"

#include <Windows.h>    

#include <Aclapi.h>     
#include <sddl.h>       
#include <tchar.h>      


#include "../../Process/Process.hpp"
#include "../../Process/Exports.hpp"
#include "../AntiTamper/remap.hpp"

#include "../Utils/utils.h"
#include "../Utils/xorstr.h"
#include "../LogSystem/Log.h"


bool Preventions::RestrictProcessAccess( ) {
	HANDLE hProcess = GetCurrentProcess( );
	PSECURITY_DESCRIPTOR pSD = NULL;
	PACL pOldDACL = NULL , pNewDACL = NULL;
	EXPLICIT_ACCESS ea = { 0 };
	PSID pEveryoneSID = NULL;
	SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;


	if ( GetSecurityInfo( hProcess , SE_KERNEL_OBJECT , DACL_SECURITY_INFORMATION ,
		NULL , NULL , &pOldDACL , NULL , &pSD ) != ERROR_SUCCESS ) {
		return false;
	}


	if ( !AllocateAndInitializeSid( &SIDAuthWorld , 1 ,
		SECURITY_WORLD_RID ,
		0 , 0 , 0 , 0 , 0 , 0 , 0 ,
		&pEveryoneSID ) ) {
		if ( pSD ) LocalFree( pSD );
		return false;
	}

	ea.grfAccessPermissions = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE;
	ea.grfAccessMode = DENY_ACCESS;
	ea.grfInheritance = NO_INHERITANCE;
	ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	ea.Trustee.ptstrName = ( LPSTR ) pEveryoneSID;

	if ( SetEntriesInAcl( 1 , &ea , pOldDACL , &pNewDACL ) != ERROR_SUCCESS ) {
		if ( pSD ) LocalFree( pSD );
		if ( pEveryoneSID ) FreeSid( pEveryoneSID );
		return false;
	}

	if ( SetSecurityInfo( hProcess , SE_KERNEL_OBJECT , DACL_SECURITY_INFORMATION ,
		NULL , NULL , pNewDACL , NULL ) != ERROR_SUCCESS ) {
		if ( pSD ) LocalFree( pSD );
		if ( pEveryoneSID ) FreeSid( pEveryoneSID );
		if ( pNewDACL ) LocalFree( pNewDACL );
		return false;
	}

	if ( pSD ) LocalFree( pSD );
	if ( pEveryoneSID ) FreeSid( pEveryoneSID );
	if ( pNewDACL ) LocalFree( pNewDACL );

	return true;
}
bool Preventions::RemapProgramSections( ) {
	ULONG_PTR ImageBase = ( ULONG_PTR ) GetModuleHandle( NULL );
	bool remap_succeeded = false;

	if ( ImageBase )
	{
		__try
		{
			if ( !RmpRemapImage( ImageBase ) ) //re-mapping of image to stop patching, and of course we can easily detect if someone bypasses this
			{
				std::cout << xorstr_( "RmpRemapImage failed.\n" );
			}
			else
			{
				//Logger::logf( "UltimateAnticheat.log" , Info , " Successfully remapped\n" );
				remap_succeeded = true;
			}
		}
		__except ( EXCEPTION_EXECUTE_HANDLER )
		{
			std::cout << xorstr_( "Remapping image failed, please ensure optimization is set to /O2\n" );
			//Logger::logf( "UltimateAnticheat.log" , Err , " Remapping image failed, please ensure optimization is set to /O2\n" );
			return false;
		}
	}
	else
	{
		std::cout << xorstr_( "Imagebase was NULL @ RemapAndCheckPages!\n" );
		//Utils::Get( ).WarnMessage( _PREVENTIONS , xorstr_( "Imagebase was NULL @ RemapAndCheckPages!" ) , RED );
		return false;
	}

	return remap_succeeded;
}

#if _WIN32_WINNT >= 0x0602  //SetProcessMitigationPolicy starts support in Windows 8 
/*
	EnableProcessMitigations - enforces policies which are actioned by the system & loader to prevent dynamic code generation & execution (unsigned code will be rejected by the loader)
*/
bool Preventions::EnableProcessMitigations( bool useDEP , bool useASLR , bool useDynamicCode , bool useStrictHandles , bool useSystemCallDisable )
{
	bool sucess = true;

	if ( useDEP )
	{
		PROCESS_MITIGATION_DEP_POLICY depPolicy = { 0 };     // DEP Policy
		depPolicy.Enable = 1;
		depPolicy.Permanent = 1;

		if ( !SetProcessMitigationPolicy( ProcessDEPPolicy , &depPolicy , sizeof( depPolicy ) ) ) {
			DWORD error = GetLastError( );
			if ( error != ERROR_NOT_SUPPORTED ) {
				Utils::Get( ).WarnMessage( _PREVENTIONS , xorstr_( "Failed to set DEP policy @ EnableProcessMitigations: " ) + std::to_string( error ) , RED );
				sucess = false;
			}
			else {
				Utils::Get( ).WarnMessage( _PREVENTIONS , xorstr_( "DEP Policy not supported on this OS version." ) , YELLOW );
			}
		}
	}

	if ( useASLR )
	{
		PROCESS_MITIGATION_ASLR_POLICY aslrPolicy = { 0 };     //ASLR Policy
		aslrPolicy.EnableBottomUpRandomization = 1;
		aslrPolicy.EnableForceRelocateImages = 1;
		aslrPolicy.EnableHighEntropy = 1;
		aslrPolicy.DisallowStrippedImages = 1;

		if ( !SetProcessMitigationPolicy( ProcessASLRPolicy , &aslrPolicy , sizeof( aslrPolicy ) ) )
		{
			DWORD error = GetLastError( );
			if ( error != ERROR_NOT_SUPPORTED ) {
				Utils::Get( ).WarnMessage( _PREVENTIONS , xorstr_( "Failed to set ASLR policy @ EnableProcessMitigations:" ) + std::to_string( error ) , RED );
				sucess = false;
			}
			else {
				Utils::Get( ).WarnMessage( _PREVENTIONS , xorstr_( "ASLR policy not supported on this OS version." ) , YELLOW );
			}
		}
	}

	if ( useDynamicCode )
	{
		PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynamicCodePolicy = { 0 };     //Dynamic Code Policy -> can prevent VirtualProtect calls on .text sections of loaded modules from working
		dynamicCodePolicy.ProhibitDynamicCode = 1;

		if ( !SetProcessMitigationPolicy( ProcessDynamicCodePolicy , &dynamicCodePolicy , sizeof( dynamicCodePolicy ) ) )
		{

			DWORD error = GetLastError( );
			if ( error != ERROR_NOT_SUPPORTED ) {
				Utils::Get( ).WarnMessage( _PREVENTIONS , xorstr_( "Failed to set dynamic code policy@ EnableProcessMitigations:" ) + std::to_string( error ) , RED );
				sucess = false;
			}
			else {
				Utils::Get( ).WarnMessage( _PREVENTIONS , xorstr_( "Dynamic code policy not supported on this OS version." ) , YELLOW );
			}
		}
	}

	if ( useStrictHandles )
	{
		PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY handlePolicy = { 0 };     // Strict Handle Check Policy
		handlePolicy.RaiseExceptionOnInvalidHandleReference = 1;
		handlePolicy.HandleExceptionsPermanentlyEnabled = 1;

		if ( !SetProcessMitigationPolicy( ProcessStrictHandleCheckPolicy , &handlePolicy , sizeof( handlePolicy ) ) )
		{
			DWORD error = GetLastError( );
			if ( error != ERROR_NOT_SUPPORTED ) {
				Utils::Get( ).WarnMessage( _PREVENTIONS , xorstr_( "Failed to set strict handle check policy @ EnableProcessMitigations:" ) + std::to_string( error ) , RED );
				sucess = false;
			}
			else {
				Utils::Get( ).WarnMessage( _PREVENTIONS , xorstr_( "Strict handle check policy not supported on this OS version." ) , YELLOW );
			}
		}
	}

	if ( useSystemCallDisable )
	{
		PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY syscallPolicy = { 0 };     // System Call Disable Policy
		syscallPolicy.DisallowWin32kSystemCalls = 1;

		if ( !SetProcessMitigationPolicy( ProcessSystemCallDisablePolicy , &syscallPolicy , sizeof( syscallPolicy ) ) )
		{
			DWORD error = GetLastError( );
			if ( error != ERROR_NOT_SUPPORTED ) {
				Utils::Get( ).WarnMessage( _PREVENTIONS , xorstr_( "Failed to set system call disable policy @ EnableProcessMitigations:" ) + std::to_string( error ) , RED );
				sucess = false;
			}
			else {
				Utils::Get( ).WarnMessage( _PREVENTIONS , xorstr_( "System call disable policy not supported on this OS version." ) , YELLOW );
			}
		}
	}
	system( "pause" );
	return sucess;
}

#endif

bool Preventions::RandomizeModuleName( )
{
	bool success = false;

	std::string OriginalModuleName = xorstr_( "aegis.exe" );

	int moduleNameSize = OriginalModuleName.size( );

	if ( moduleNameSize == 0 )
	{
		return false;
	}

	std::string * newModuleName = new string;
	newModuleName->reserve( moduleNameSize );

	*newModuleName = Utils::Get( ).GenerateRandomKey( moduleNameSize - 1 ) + xorstr_( "\0" ); //intentionally set to -2 to trip up external programs like CE from enumerating dlls & symbols

	wstring wStrNewModuleName( newModuleName->begin( ) , newModuleName->end( ) );
	wstring wStrOriginalModuleName( OriginalModuleName.begin( ) , OriginalModuleName.end( ) );

	if ( Process::ChangeModuleName( wStrOriginalModuleName.c_str( ) , wStrNewModuleName.c_str( ) ) ) //in addition to changing export function names, we can also modify the names of loaded modules/libraries.
	{
		success = true;
		/*UnmanagedGlobals::wCurrentModuleName = wstring( newModuleName );
		UnmanagedGlobals::CurrentModuleName = Utility::ConvertWStringToString( UnmanagedGlobals::wCurrentModuleName );*/
		Utils::Get( ).WarnMessage( _PREVENTIONS , xorstr_( "changed module name to " ) + *newModuleName , GREEN );

		// Logger::logfw( "UltimateAnticheat.log" , Info , L"Changed module name to: %s\n" , UnmanagedGlobals::wCurrentModuleName.c_str( ) );
	}
	std::fill( newModuleName->begin( ) , newModuleName->end( ) , '\0' );
	delete newModuleName;
	return success;
}

bool Preventions::StopAPCInjection( )
{
	HMODULE ntdll = GetModuleHandleA( "ntdll.dll" );

	if ( !ntdll )
	{
		std::cout << xorstr_( "Failed to get ntdll address @ Stop\n" );
		DWORD error = GetLastError( );
		return false;
	}

	const int Ordinal = 8;
	UINT64 Oridinal8 = ( UINT64 ) GetProcAddress( ntdll , MAKEINTRESOURCEA( Ordinal ) ); //TODO: make sure Ordinal8 exists on other versions of windows and is the same function

	if ( !Oridinal8 )
	{
		DWORD error = GetLastError( );
		std::cout << xorstr_( "Failed to get Oridinal8 address @ Stop\n" );
		return false;
	}

	__try
	{
		DWORD dwOldProt = 0;

		if ( !VirtualProtect( ( LPVOID ) Oridinal8 , sizeof( std::byte ) , PAGE_EXECUTE_READWRITE , &dwOldProt ) )
		{
			std::cout << xorstr_( "Failed to call VirtualProtect on Oridinal8 address @ Stop\n");
			return false;
		}
		else
		{
			if ( Oridinal8 != 0 )
				*( BYTE * ) Oridinal8 = 0xC3;

			VirtualProtect( ( LPVOID ) Oridinal8 , sizeof( std::byte ) , dwOldProt , &dwOldProt );
		}

	}
	__except ( EXCEPTION_EXECUTE_HANDLER )
	{
		std::cout << xorstr_( "Failed to patch over Ordinal8 address @ Stop\n" );
		return false;
	}

	return true;
}


bool Preventions::PreventDllInjection( )
{
	bool success = FALSE;

	//Anti-dll injection
	char * RandString1 = Utils::Get( ).GenerateRandomString( 12 );
	char * RandString2 = Utils::Get( ).GenerateRandomString( 12 );
	char * RandString3 = Utils::Get( ).GenerateRandomString( 14 );
	char * RandString4 = Utils::Get( ).GenerateRandomString( 14 );

	//prevents DLL injection from any host process relying on calling LoadLibrary in the target process (we are the target in this case) -> can possibly be disruptive to end user
	if ( Exports::ChangeFunctionName( xorstr_( "KERNEL32.DLL" ) , xorstr_( "LoadLibraryA" ) , RandString1 ) &&
		Exports::ChangeFunctionName( xorstr_( "KERNEL32.DLL" ) , xorstr_( "LoadLibraryW" ) , RandString2 ) &&
		Exports::ChangeFunctionName( xorstr_( "KERNEL32.DLL" ) , xorstr_( "LoadLibraryExA" ) , RandString3 ) &&
		Exports::ChangeFunctionName( xorstr_( "KERNEL32.DLL" ) , xorstr_( "LoadLibraryExW" ) , RandString4 ) )
	{
		success = TRUE;
	}
	else
	{
		success = FALSE;
	}

	delete[ ] RandString1; RandString1 = nullptr;
	delete[ ] RandString2; RandString2 = nullptr;
	delete[ ] RandString3; RandString3 = nullptr;
	delete[ ] RandString4; RandString4 = nullptr;

	return success;
}

void Preventions::Deploy( ) {
	if ( !Preventions::Get( ).RemapProgramSections( ) ) {
		LogSystem::Get( ).Log( xorstr_( "[0] Failed to protect process" ) );
	}
	if ( !Preventions::Get( ).RestrictProcessAccess( ) ) {
		LogSystem::Get( ).Log( xorstr_( "[1] Failed to protect process" ) );
	}
	if ( !Preventions::Get( ).RandomizeModuleName( ) ) {
		LogSystem::Get( ).Log( xorstr_( "[2] Failed to protect process" ) );
	}
	if ( !Preventions::Get( ).EnableProcessMitigations( true , true , false , true , false ) ) {
		LogSystem::Get( ).Log( xorstr_( "[3] Failed to protect process" ) );
	}
	if ( !Preventions::Get( ).PreventDllInjection( ) ) {
		LogSystem::Get( ).Log( xorstr_( "[4] Failed to protect process" ) );
	}
}