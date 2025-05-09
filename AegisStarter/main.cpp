#include <iostream>
#include <windows.h>
#include <tlhelp32.h>

#include "Globals/globals.h"
#include "Utils/File/File.h"
#include "Utils/xorstr.h"
#include "Systems/LogSystem/Log.h"
#include "Systems/ManualMapper/Injection.h"

bool CreateSuspendedProcess( const char * executablePath , const char * args , PROCESS_INFORMATION & pi ) {
	STARTUPINFOA si = { sizeof( STARTUPINFOA ) };

	std::string commandLine = std::string( "\"" ) + executablePath + "\" " + args;

	if ( !CreateProcessA(
		nullptr ,
		( LPSTR ) commandLine.c_str( ) , // Usa a linha de comando completa
		nullptr ,
		nullptr ,
		FALSE ,
		CREATE_SUSPENDED ,
		nullptr ,
		nullptr ,
		&si ,
		&pi
	) ) {
		std::cerr << "Falha ao criar processo suspenso. Erro: " << GetLastError( ) << std::endl;
		return false;
	}

	return true;
}

bool InjectDLL( DWORD processId , const char * dllPath ) {
	HANDLE hProcess = OpenProcess( PROCESS_ALL_ACCESS , FALSE , processId );
	if ( !hProcess ) {
		std::cerr << "Falha ao abrir o processo. Erro: " << GetLastError( ) << std::endl;
		return false;
	}

	LPVOID remoteMemory = VirtualAllocEx( hProcess , nullptr , strlen( dllPath ) + 1 , MEM_COMMIT , PAGE_READWRITE );
	if ( !remoteMemory ) {
		std::cerr << "Falha ao alocar memória. Erro: " << GetLastError( ) << std::endl;
		CloseHandle( hProcess );
		return false;
	}

	if ( !WriteProcessMemory( hProcess , remoteMemory , dllPath , strlen( dllPath ) + 1 , nullptr ) ) {
		std::cerr << "Falha ao escrever na memória. Erro: " << GetLastError( ) << std::endl;
		VirtualFreeEx( hProcess , remoteMemory , 0 , MEM_RELEASE );
		CloseHandle( hProcess );
		return false;
	}

	HMODULE ModuleHandle = GetModuleHandleA( "kernel32.dll" );

	if ( ModuleHandle == NULL ) {
		std::cerr << "Falha ao obter kernel32.dll. Erro: " << GetLastError( ) << std::endl;
		return false;
	}

	LPVOID loadLibraryAddr = ( LPVOID ) GetProcAddress( ModuleHandle , "LoadLibraryA" );
	if ( !loadLibraryAddr ) {
		std::cerr << "Falha ao obter endereço de LoadLibraryA. Erro: " << GetLastError( ) << std::endl;
		VirtualFreeEx( hProcess , remoteMemory , 0 , MEM_RELEASE );
		CloseHandle( hProcess );
		return false;
	}

	HANDLE hThread = CreateRemoteThread( hProcess , nullptr , 0 , ( LPTHREAD_START_ROUTINE ) loadLibraryAddr , remoteMemory , 0 , nullptr );
	if ( !hThread ) {
		std::cerr << "Falha ao criar thread remota. Erro: " << GetLastError( ) << std::endl;
		VirtualFreeEx( hProcess , remoteMemory , 0 , MEM_RELEASE );
		CloseHandle( hProcess );
		return false;
	}

	WaitForSingleObject( hThread , INFINITE );
	VirtualFreeEx( hProcess , remoteMemory , 0 , MEM_RELEASE );
	CloseHandle( hThread );
	CloseHandle( hProcess );

	return true;
}

bool IsRunningAsAdmin( ) {
	BOOL isAdmin = FALSE;
	PSID adminGroup = nullptr;

	// Cria um SID para o grupo Administradores
	SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
	if ( AllocateAndInitializeSid(
		&ntAuthority , 2 ,
		SECURITY_BUILTIN_DOMAIN_RID ,
		DOMAIN_ALIAS_RID_ADMINS ,
		0 , 0 , 0 , 0 , 0 , 0 ,
		&adminGroup ) ) {
		CheckTokenMembership( nullptr , adminGroup , &isAdmin );
		FreeSid( adminGroup );
	}

	return isAdmin == TRUE;
}

// Função de callback com a assinatura correta
BOOL CALLBACK EnumResNamesProc(
	HMODULE hModule ,
	LPCWSTR lpType ,    // Corrigido para LPCWSTR (não LPWSTR)
	LPWSTR lpName ,
	LONG_PTR lParam
) {
	// Imprime o tipo e o nome do recurso
	std::wcout << L"Tipo: " << lpType << L", Nome/ID: " << lpName << std::endl;
	return TRUE;  // Continua a enumeração
}

BOOL CALLBACK EnumResTypesProc(
	HMODULE hModule ,
	LPWSTR lpType ,
	LONG_PTR lParam
) {
	std::wcout << L"Tipo de recurso: " << lpType << std::endl;
	return TRUE;
}

void ListarRecursos( const std::wstring & caminhoDLL ) {
	// Carrega a DLL
	HMODULE hModuleDep1 = LoadLibraryA( "libcrypto-1_1-x64.dll" );
	HMODULE hModuleDep2 = LoadLibraryA( "libssl-1_1-x64.dll" );

	HMODULE hModule = LoadLibraryW( caminhoDLL.c_str( ) );
	if ( hModule == NULL || hModuleDep1 == NULL || hModuleDep2 == NULL ) {
		std::cerr << "Erro ao carregar a DLL! Código do erro: " << GetLastError( ) << std::endl;
		return;
	}

	if ( !EnumResourceTypes( hModule , EnumResTypesProc , 0 ) ) {
		std::cerr << "Erro ao enumerar os tipos de recursos! Código do erro: " << GetLastError( ) << std::endl;
	}

	// Tenta enumerar os recursos do tipo RCDATA
	if ( !EnumResourceNames( hModule , NULL , EnumResNamesProc , 0 ) ) {
		std::cerr << "Erro ao enumerar os recursos! Código do erro: " << GetLastError( ) << std::endl;
	}

	// Libera a DLL
	FreeLibrary( hModule );
	FreeLibrary( hModuleDep1 );
	FreeLibrary( hModuleDep2 );
	
}


int main( int argc , char * argv[ ] ) {

	if ( !IsRunningAsAdmin( ) ) {
		LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "Launcher is not on admin mode!" ) , RED );
		return 1;
	}

	//ListarRecursos( L"aegis.dll" );

	File GameFile = _globals.GameName;
	if ( !GameFile.Exists( ) ) {
		LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "Unable to find game" ) , RED );
	}

	std::string Args = "";
	for ( int i = 0; i < argc; ++i ) {
		if ( i >= 1 ) {
			Args += argv[ i ];
			Args += xorstr_( " " );
		}
	}

	PROCESS_INFORMATION pi = { 0 };

	// 1. Cria o processo do jogo suspenso
	if ( !CreateSuspendedProcess( _globals.GameName.c_str( ) , Args.c_str( ) , pi ) ) {
		LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "Failed to create process!" ) , RED );
		return 1;
	}

	if ( pi.hProcess == NULL || pi.hThread == NULL ) {
		LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "Can't get game process!" ) , GREEN );
		return 1;
	}

	if ( !InjectDLL( pi.dwProcessId, "aegis.dll") ) {
		LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "Failed to start!" ) , RED );
		TerminateProcess( pi.hProcess , 0 ); // Encerra o processo se a injeção falhar
		CloseHandle( pi.hProcess );
		CloseHandle( pi.hThread );
		return 1;
	}

	 ResumeThread( pi.hThread );

	LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "Anti-cheat injetado com sucesso!" ) , GREEN );

	CloseHandle( pi.hProcess );
	CloseHandle( pi.hThread );

	while ( true ) {
		Sleep( 100 );
	}
}