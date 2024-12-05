#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <fstream>
#include <string>
#include <vector>

#include <mmsystem.h>

#pragma comment(lib, "winmm.lib") // Necessário para vincular à biblioteca

// Função para "drenar" a memória de um processo
bool DumpProcessMemory( DWORD processID ) {
	HANDLE hProcess = OpenProcess( PROCESS_VM_READ | PROCESS_QUERY_INFORMATION , FALSE , processID );
	if ( hProcess == nullptr ) {
		std::wcerr << L"Erro ao abrir o processo com o ID: " << processID << std::endl;
		return false;
	}

	SYSTEM_INFO sysInfo;
	GetSystemInfo( &sysInfo );

	MEMORY_BASIC_INFORMATION memInfo;
	for ( PBYTE addr = 0; addr < sysInfo.lpMaximumApplicationAddress; addr += memInfo.RegionSize ) {
		if ( VirtualQueryEx( hProcess , addr , &memInfo , sizeof( memInfo ) ) && memInfo.State == MEM_COMMIT ) {
			std::vector<BYTE> buffer( memInfo.RegionSize );
			SIZE_T bytesRead;
			if ( ReadProcessMemory( hProcess , addr , buffer.data( ) , memInfo.RegionSize , &bytesRead ) ) {
				// Salvando conteúdo da memória em arquivo
				std::ofstream outFile( "memory_dump.bin" , std::ios::binary | std::ios::app );
				outFile.write( reinterpret_cast< char * >( buffer.data( ) ) , bytesRead );
			}
		}
	}

	CloseHandle( hProcess );
	return true;
}

// Função para injetar código em outro processo
bool InjectCode( DWORD processID ) {
	HANDLE hProcess = OpenProcess( PROCESS_ALL_ACCESS , FALSE , processID );
	if ( hProcess == nullptr ) {
		std::wcerr << L"Erro ao abrir o processo para injeção: " << processID << std::endl;
		return false;
	}



	// Código para ser injetado
	const char * dllPath = "C:\\meu_cheat.dll";
	size_t pathLen = strlen( dllPath ) + 1;

	// Aloca memória no processo alvo
	LPVOID remoteMemory = VirtualAllocEx( hProcess , nullptr , pathLen , MEM_RESERVE | MEM_COMMIT , PAGE_READWRITE );
	if ( !remoteMemory ) {
		CloseHandle( hProcess );
		return false;
	}

	// Escreve o caminho da DLL na memória alocada
	WriteProcessMemory( hProcess , remoteMemory , dllPath , pathLen , nullptr );

	// Executa LoadLibraryA na memória remota
	HANDLE hThread = CreateRemoteThread( hProcess , nullptr , 0 ,
		reinterpret_cast< LPTHREAD_START_ROUTINE >( GetProcAddress( GetModuleHandle( "kernel32.dll" ) , "LoadLibraryA" ) ) ,
		remoteMemory , 0 , nullptr );
	if ( hThread ) {
		WaitForSingleObject( hThread , INFINITE );
		CloseHandle( hThread );
	}

	VirtualFreeEx( hProcess , remoteMemory , 0 , MEM_RELEASE );
	CloseHandle( hProcess );
	return true;
}

// Obter PID de processo por nome
DWORD GetProcessID( const std::string & processName ) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS , 0 );
	if ( hSnapshot == INVALID_HANDLE_VALUE ) {
		std::wcerr << L"Erro ao criar snapshot de processos." << std::endl;
		return NULL;
	}

	PROCESSENTRY32 processEntry;
	processEntry.dwSize = sizeof( PROCESSENTRY32 );

	if ( Process32First( hSnapshot , &processEntry ) ) {
		do {
			if ( processName == processEntry.szExeFile ) {
				CloseHandle( hSnapshot );
				return processEntry.th32ProcessID;
			}
		} while ( Process32Next( hSnapshot , &processEntry ) );
	}

	std::wcerr << L"Processo não encontrado." << std::endl;
	CloseHandle( hSnapshot );
	return NULL;
}

// Manipulação de threads para ocultação
void EnumerateThreads( DWORD processID ) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD , 0 );
	if ( hSnapshot == INVALID_HANDLE_VALUE ) {
		std::wcerr << L"Erro ao criar snapshot de threads." << std::endl;
		return;
	}

	THREADENTRY32 threadEntry;
	threadEntry.dwSize = sizeof( THREADENTRY32 );

	if ( Thread32First( hSnapshot , &threadEntry ) ) {
		do {
			if ( threadEntry.th32OwnerProcessID == processID ) {
				HANDLE hThread = OpenThread( THREAD_SUSPEND_RESUME , FALSE , threadEntry.th32ThreadID );
				if ( hThread ) {
					SuspendThread( hThread ); // Exemplo de manipulação
					ResumeThread( hThread );
					CloseHandle( hThread );
				}
			}
		} while ( Thread32Next( hSnapshot , &threadEntry ) );
	}

	CloseHandle( hSnapshot );
}

int main( ) {
	PlaySound( TEXT( "c:\\hit2.wav" ) , NULL , SND_FILENAME /*| SND_ASYNC*/ );
	//std::string processName = "DayZ_x64.exe";  // Nome do processo alvo
	//DWORD processID = GetProcessID( processName );

	//if ( processID ) {
	//	std::cout << "Processo encontrado. ID: " << processID << std::endl;
	//	system( "pause" );
	//	// Exemplo de dump de memória
	//	DumpProcessMemory( processID );

	//	// Exemplo de injeção de código
	//	//InjectCode( processID );

	//	// Manipulação de threads
	//	EnumerateThreads( processID );
	//}
	//else {
	//	std::cerr << "Processo não encontrado!" << std::endl;
	//}

	//// Loop infinito para simular persistência
	//while ( true ) {
	//	Sleep( 100 );
	//}

	return 0;
}
