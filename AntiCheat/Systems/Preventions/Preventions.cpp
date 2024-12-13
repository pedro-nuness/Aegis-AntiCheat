#include "Preventions.h"

#include <Windows.h>    

#include <Aclapi.h>     
#include <sddl.h>       
#include <tchar.h>      
#include <sstream>
#include <iomanip>

#include "../../Process/Process.hpp"
#include "../../Process/Exports.hpp"
#include "../AntiTamper/remap.hpp"

#include "../Utils/utils.h"
#include "../Utils/xorstr.h"
#include "../LogSystem/Log.h"
#include "../../Obscure/ntldr.h"

#include "../../externals/minhook/MinHook.h"

#include "../../Modules/Detections/Detections.h"
#include "../../Globals/Globals.h"

#include <Windows.h>
#include <iostream>


bool Preventions::RestrictProcessAccess( ) {
	HANDLE hProcess = GetCurrentProcess( );
	PSECURITY_DESCRIPTOR pSD = NULL;
	PACL pDacl = NULL;
	EXPLICIT_ACCESSA ea = { 0 };
	SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
	PSID pEveryoneSID = NULL;
	PSID pAdminSID = NULL;
	PSID pSystemSID = NULL;

	// Criar SID para "Everyone".
	if ( !AllocateAndInitializeSid(
		&SIDAuthWorld , 1 , SECURITY_WORLD_RID ,
		0 , 0 , 0 , 0 , 0 , 0 , 0 , &pEveryoneSID ) ) {
		LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "Falha ao inicializar SID para Everyone." ) , YELLOW );
		return false;
	}

	// Criar SID para administradores.
	SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
	if ( !AllocateAndInitializeSid(
		&SIDAuthNT , 2 , SECURITY_BUILTIN_DOMAIN_RID ,
		DOMAIN_ALIAS_RID_ADMINS , 0 , 0 , 0 , 0 , 0 , 0 , &pAdminSID ) ) {
		LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "Falha ao inicializar SID para Administradores" ) , YELLOW );
		FreeSid( pEveryoneSID );
		return false;
	}

	// Criar SID para SYSTEM.
	if ( !AllocateAndInitializeSid(
		&SIDAuthNT , 1 , SECURITY_LOCAL_SYSTEM_RID ,
		0 , 0 , 0 , 0 , 0 , 0 , 0 , &pSystemSID ) ) {
		LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "Falha ao inicializar SID para SYSTEM" ) , YELLOW );
		FreeSid( pEveryoneSID );
		FreeSid( pAdminSID );
		return false;
	}


	// Configurar estrutura de acesso explícito para negar todas as permissões para cada SID.
	ea.grfAccessPermissions = PROCESS_ALL_ACCESS;
	ea.grfAccessMode = DENY_ACCESS;
	ea.grfInheritance = NO_INHERITANCE;

	// Negar para "Everyone"
	ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	ea.Trustee.ptstrName = ( LPSTR ) pEveryoneSID;

	// Criar ACL para negar "Everyone".
	DWORD result = SetEntriesInAclA( 1 , &ea , NULL , &pDacl );
	if ( result != ERROR_SUCCESS ) {
		LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "Falha ao configurar entradas de ACL para Everyone" ) , YELLOW );
		FreeSid( pEveryoneSID );
		FreeSid( pAdminSID );
		FreeSid( pSystemSID );
		return false;
	}

	// Repetir para Administradores.
	ea.Trustee.ptstrName = ( LPSTR ) pAdminSID;
	result = SetEntriesInAclA( 1 , &ea , pDacl , &pDacl );
	if ( result != ERROR_SUCCESS ) {
		LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "Falha ao configurar entradas de ACL para Administradores" ) , YELLOW );
		FreeSid( pEveryoneSID );
		FreeSid( pAdminSID );
		FreeSid( pSystemSID );
		return false;
	}

	// Repetir para SYSTEM.
	ea.Trustee.ptstrName = ( LPSTR ) pSystemSID;
	result = SetEntriesInAclA( 1 , &ea , pDacl , &pDacl );
	if ( result != ERROR_SUCCESS ) {
		LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "Falha ao configurar entradas de ACL para SYSTEM" ) , YELLOW );
		FreeSid( pEveryoneSID );
		FreeSid( pAdminSID );
		FreeSid( pSystemSID );
		return false;
	}

	// Criar um novo descritor de segurança.
	pSD = ( PSECURITY_DESCRIPTOR ) LocalAlloc( LPTR , SECURITY_DESCRIPTOR_MIN_LENGTH );
	if ( !pSD || !InitializeSecurityDescriptor( pSD , SECURITY_DESCRIPTOR_REVISION ) ) {
		LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "Falha ao inicializar o descritor de segurança" ) , YELLOW );
		FreeSid( pEveryoneSID );
		FreeSid( pAdminSID );
		FreeSid( pSystemSID );
		return false;
	}

	// Configurar a nova ACL no descritor de segurança.
	if ( !SetSecurityDescriptorDacl( pSD , TRUE , pDacl , FALSE ) ) {
		LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "Falha ao configurar a DACL" ) , YELLOW );
		FreeSid( pEveryoneSID );
		FreeSid( pAdminSID );
		FreeSid( pSystemSID );
		return false;
	}

	// Aplicar o descritor de segurança ao processo.
	if ( SetKernelObjectSecurity( hProcess , DACL_SECURITY_INFORMATION , pSD ) == 0 ) {
		LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "Falha ao aplicar informações de segurança" ) , YELLOW );
		FreeSid( pEveryoneSID );
		FreeSid( pAdminSID );
		FreeSid( pSystemSID );
		return false;
	}

	// Liberar recursos.
	FreeSid( pEveryoneSID );
	FreeSid( pAdminSID );
	FreeSid( pSystemSID );
	LocalFree( pSD );

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
		//LogSystem::Get( ).ConsoleLog( _PREVENTIONS , xorstr_( "Imagebase was NULL @ RemapAndCheckPages!" ) , RED );
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
				LogSystem::Get( ).ConsoleLog( _PREVENTIONS , xorstr_( "Failed to set DEP policy @ EnableProcessMitigations: " ) + std::to_string( error ) , RED );
				sucess = false;
			}
			else {
				LogSystem::Get( ).ConsoleLog( _PREVENTIONS , xorstr_( "DEP Policy not supported on this OS version." ) , YELLOW );
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
				LogSystem::Get( ).ConsoleLog( _PREVENTIONS , xorstr_( "Failed to set ASLR policy @ EnableProcessMitigations:" ) + std::to_string( error ) , RED );
				sucess = false;
			}
			else {
				LogSystem::Get( ).ConsoleLog( _PREVENTIONS , xorstr_( "ASLR policy not supported on this OS version." ) , YELLOW );
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
				LogSystem::Get( ).ConsoleLog( _PREVENTIONS , xorstr_( "Failed to set dynamic code policy@ EnableProcessMitigations:" ) + std::to_string( error ) , RED );
				sucess = false;
			}
			else {
				LogSystem::Get( ).ConsoleLog( _PREVENTIONS , xorstr_( "Dynamic code policy not supported on this OS version." ) , YELLOW );
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
				LogSystem::Get( ).ConsoleLog( _PREVENTIONS , xorstr_( "Failed to set strict handle check policy @ EnableProcessMitigations:" ) + std::to_string( error ) , RED );
				sucess = false;
			}
			else {
				LogSystem::Get( ).ConsoleLog( _PREVENTIONS , xorstr_( "Strict handle check policy not supported on this OS version." ) , YELLOW );
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
				LogSystem::Get( ).ConsoleLog( _PREVENTIONS , xorstr_( "Failed to set system call disable policy @ EnableProcessMitigations:" ) + std::to_string( error ) , RED );
				sucess = false;
			}
			else {
				LogSystem::Get( ).ConsoleLog( _PREVENTIONS , xorstr_( "System call disable policy not supported on this OS version." ) , YELLOW );
			}
		}
	}
	return sucess;
}

#endif

std::string GetBaseModuleName( ) {
	char moduleName[ MAX_PATH ] = { 0 };

	// Obter o handle do módulo atual (NULL significa o módulo do processo atual)
	if ( GetModuleFileNameA( NULL , moduleName , MAX_PATH ) ) {
		// Converter para uma std::string
		std::string fullPath( moduleName );

		// Encontrar a posição do último separador de caminho
		size_t pos = fullPath.find_last_of( "\\/" );
		if ( pos != std::string::npos ) {
			// Retornar apenas o nome do arquivo
			return fullPath.substr( pos + 1 );
		}

		return fullPath; // Retorna o caminho completo se nenhum separador for encontrado
	}

	return "";
}

bool Preventions::RandomizeModuleName( )
{
	bool success = false;

	std::string OriginalModuleName = GetBaseModuleName( );
	if ( OriginalModuleName.empty( ) )
		return false;

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
		// LogSystem::Get( ).ConsoleLog( _PREVENTIONS , xorstr_( "changed module name to " ) + *newModuleName , GREEN );

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
			std::cout << xorstr_( "Failed to call VirtualProtect on Oridinal8 address @ Stop\n" );
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

/*
	PreventShellcodeThreads - changes export routine name of K32's CreateThread such that external attackers cannot look up the functions address.
	 *Note* : Changing export names for certain important dll routines can result in popup errors for the end-user, thus its not recommended for a live product. Alternatively, routines can have their function preambles 'ret' patched for similar effects (if you know it wont impact program functionality).
*/
bool Preventions::PreventThreadCreation( ) {
	bool success = FALSE;
	char * RandString1 = Utils::Get( ).GenerateRandomString( 12 );

	if ( Exports::ChangeFunctionName( xorstr_( "KERNEL32.DLL" ) , xorstr_( "CreateThread" ) , RandString1 ) )
		success = TRUE;

	delete[ ] RandString1;
	RandString1 = nullptr;
	return success;

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

bool Preventions::DeployDllLoadNotifation( ) {
	//HMODULE hNtdll = GetModuleHandleA( xorstr_( "ntdll.dll" ) );
	//if ( hNtdll != 0 ) //register DLL notifications callback 
	//{
	//	_LdrRegisterDllNotification pLdrRegisterDllNotification = ( _LdrRegisterDllNotification ) GetProcAddress( hNtdll , "LdrRegisterDllNotification" );
	//	PVOID cookie;
	//	NTSTATUS status = pLdrRegisterDllNotification( 0 , ( PLDR_DLL_NOTIFICATION_FUNCTION ) Detecions::OnDllNotification , this , &cookie );
	//}
}

BOOL SuspectThreadAddress( LPVOID lpStartAddress )
{
	MEMORY_BASIC_INFORMATION mbi;
	// Obtemos a informação sobre a região de memória onde o thread foi alocado
	if ( VirtualQuery( lpStartAddress , &mbi , sizeof( mbi ) ) == 0 )
	{
		return TRUE;  // Se a consulta falhar, o endereço é inválido
	}

	// Verifica se a região de memória é válida para threads (não deve ser uma área de código ou dados suspeitos)
	// Por exemplo, vamos verificar se o endereço está no espaço de heap ou pilha
	if ( mbi.State == MEM_COMMIT && ( mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED ) )
	{
		return TRUE;
	}

	return FALSE;
}

typedef HANDLE( WINAPI * pCreateThread )(
	LPSECURITY_ATTRIBUTES lpThreadAttributes ,
	SIZE_T dwStackSize ,
	LPTHREAD_START_ROUTINE lpStartAddress ,
	LPVOID lpParameter ,
	DWORD dwCreationFlags ,
	LPDWORD lpThreadId
	);

std::string GenerateInvalidThreadLog(
	LPSECURITY_ATTRIBUTES lpThreadAttributes ,
	SIZE_T dwStackSize ,
	LPTHREAD_START_ROUTINE lpStartAddress ,
	LPVOID lpParameter ,
	DWORD dwCreationFlags ,
	LPDWORD lpThreadId )
{
	std::ostringstream log;

	log << xorstr_( "Thread Creation Details:\n");

	log << xorstr_( "lpThreadAttributes: ");
	if ( lpThreadAttributes ) {
		log << xorstr_( "Present (nLength: ") << lpThreadAttributes->nLength << xorstr_( ", lpSecurityDescriptor: ")
			<< lpThreadAttributes->lpSecurityDescriptor << xorstr_( ", bInheritHandle: " )
			<< ( lpThreadAttributes->bInheritHandle ? xorstr_( "true") : xorstr_( "false") ) << xorstr_( ")");
	}
	else {
		log << xorstr_( "nullptr");
	}
	log << xorstr_( "\n");

	log << xorstr_( "dwStackSize: ") << dwStackSize << xorstr_( " bytes\n");

	log << xorstr_( "lpStartAddress: ") << std::hex << std::setw( sizeof( void * ) * 2 ) << std::setfill( '0' )
		<< reinterpret_cast< void * >( lpStartAddress ) << "\n";

	log << xorstr_( "lpParameter: ") << std::hex << std::setw( sizeof( void * ) * 2 ) << std::setfill( '0' )
		<< reinterpret_cast< void * >( lpParameter ) << "\n";

	log << xorstr_( "dwCreationFlags: 0x") << std::hex << dwCreationFlags << "\n";

	log << xorstr_( "lpThreadId: ");
	if ( lpThreadId ) {
		log << *lpThreadId;
	}
	else {
		log << xorstr_( "nullptr" );
	}
	log << xorstr_( "\n");

	return log.str( );
}


pCreateThread originalCreateThread = nullptr;

HANDLE WINAPI MyCreateThread(
	LPSECURITY_ATTRIBUTES lpThreadAttributes ,
	SIZE_T dwStackSize ,
	LPTHREAD_START_ROUTINE lpStartAddress ,
	LPVOID lpParameter ,
	DWORD dwCreationFlags ,
	LPDWORD lpThreadId
) {

	//somehow, this mf managed to get the createthread function pointer, and called it, so let's check

	MEMORY_BASIC_INFORMATION mbi;
	// Obtemos a informação sobre a região de memória onde o thread foi alocado
	if ( VirtualQuery( lpStartAddress , &mbi , sizeof( mbi ) ) )
	{
		if ( mbi.Type != MEM_IMAGE ) {
			if ( _globals.DetectionsPointer != nullptr ) {
				Detections * DetectionPtr = reinterpret_cast< Detections * > ( _globals.DetectionsPointer );
				DetectionPtr->AddExternalDetection( INVALID_THREAD_CREATION , DetectionStruct( GenerateInvalidThreadLog( lpThreadAttributes ,
					dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId
					) , DETECTED ) );
			}

			LogSystem::Get( ).ConsoleLog( _PREVENTIONS , xorstr_( "Invalid thread creation attempted" ) , RED );
			return NULL;
		}
	}


	// Call the original CreateThread function
	return originalCreateThread(
		lpThreadAttributes ,
		dwStackSize ,
		lpStartAddress ,
		lpParameter ,
		dwCreationFlags ,
		lpThreadId
	);
}

// Function to unhook CreateThread
bool UnhookApis( ) {
	// Disable the hook
	if ( MH_DisableHook( MH_ALL_HOOKS ) != MH_OK ) {
		LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "Failed to disable hook!" ) , YELLOW );
		return false;
	}

	// Uninitialize MinHook
	if ( MH_Uninitialize( ) != MH_OK ) {
		LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "MinHook uninitialization failed!" ) , YELLOW );
		return false;
	}
	return true;
}

bool Preventions::EnableApiHooks( ) {

	if ( MH_Initialize( ) != MH_OK ) {
		LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "MinHook initialization failed!" ) , YELLOW );
		return false;
	}

	if ( MH_CreateHookApi( L"kernel32.dll" , "CreateThread" , &MyCreateThread , reinterpret_cast< LPVOID * >( &originalCreateThread ) ) != MH_OK ) {
		LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "Failed to create hook for CreateThread!" ) , YELLOW );
		return false;
	}

	if ( MH_EnableHook( MH_ALL_HOOKS ) != MH_OK ) {
		LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "Failed to enable hooks!" ) , YELLOW );
		return false;
	}

	return true;
}

void Preventions::Deploy( ) {

	if ( !Preventions::Get( ).RestrictProcessAccess( ) )
		LogSystem::Get( ).Log( xorstr_( "[0] Failed to protect process" ) );

	if ( !Preventions::Get().EnableApiHooks( ) ) 
		LogSystem::Get( ).Log( xorstr_( "[1] Failed to protect process" ) );
	
	if ( !Preventions::Get( ).RandomizeModuleName( ) )
		LogSystem::Get( ).Log( xorstr_( "[2] Failed to protect process" ) );

	if ( !Preventions::Get( ).PreventDllInjection( ) )
		LogSystem::Get( ).Log( xorstr_( "[3] Failed to protect process" ) );

	if(!Preventions::Get().PreventThreadCreation() )
		LogSystem::Get( ).Log( xorstr_( "[4] Failed to protect process" ) );


	/*if ( !Preventions::Get( ).RemapProgramSections( ) ) {
		LogSystem::Get( ).Log( xorstr_( "[0] Failed to protect process" ) );
	}

	if ( !Preventions::Get( ).EnableProcessMitigations( true , true , false , true , false ) ) {
		LogSystem::Get( ).Log( xorstr_( "[3] Failed to protect process" ) );
	}*/

	LogSystem::Get( ).ConsoleLog( _PREVENTIONS , xorstr_( "deployed sucessfully" ) , GREEN );

}

