#include "Detections.h"

#include <iostream>
#include <Windows.h>
#include <vector>
#include <thread>
#include <tlhelp32.h>
#include <psapi.h>
#include <unordered_map>
#include <dbghelp.h>

#pragma comment(lib, "dbghelp.lib")

#include "../../Systems/Utils/utils.h"
#include  "../../Systems/Memory/memory.h"
#include "../../Systems/Utils/xorstr.h"
#include "../../Systems/Injection/Injection.h"
#include "../../Systems/LogSystem/Log.h"

Detections::Detections( ) {

}

Detections::~Detections( ) {

}

void Detections::start( ) {
	m_running = true;
	m_thread = std::thread( &Detections::threadFunction , this );
}

void Detections::stop( ) {
	m_running = false;
	if ( m_thread.joinable( ) ) {
		m_thread.join( );
	}
}

bool Detections::isRunning( ) const {
	return m_running && m_healthy;
}

void Detections::reset( ) {
	// Implementation to reset the thread
	std::cout << "[detections] resetting thread!\n";
	if ( m_thread.joinable( ) ) {
		m_thread.join( );
	}

	start( );
}

void Detections::requestupdate( ) {
	this->m_healthy = false;
}

bool Detections::ScanCurrentThreads( ) {

}

bool DetectIATHook( HMODULE module , const char * funcName , const char * dllName ) {
	PIMAGE_DOS_HEADER dosHeader = ( PIMAGE_DOS_HEADER ) module;
	PIMAGE_NT_HEADERS ntHeaders = ( PIMAGE_NT_HEADERS ) ( ( BYTE * ) module + dosHeader->e_lfanew );

	// Localiza o descritor de importação
	PIMAGE_IMPORT_DESCRIPTOR importDesc = ( PIMAGE_IMPORT_DESCRIPTOR ) ( ( BYTE * ) module +
		ntHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress );

	while ( importDesc->Name ) {
		const char * currDllName = ( const char * ) ( ( BYTE * ) module + importDesc->Name );
		if ( _stricmp( currDllName , dllName ) == 0 ) {
			// Verifica as funções importadas desse DLL
			PIMAGE_THUNK_DATA thunkILT = ( PIMAGE_THUNK_DATA ) ( ( BYTE * ) module + importDesc->OriginalFirstThunk );
			PIMAGE_THUNK_DATA thunkIAT = ( PIMAGE_THUNK_DATA ) ( ( BYTE * ) module + importDesc->FirstThunk );

			while ( thunkILT->u1.AddressOfData ) {
				PIMAGE_IMPORT_BY_NAME importByName = ( PIMAGE_IMPORT_BY_NAME ) ( ( BYTE * ) module + thunkILT->u1.AddressOfData );

				if ( strcmp( ( char * ) importByName->Name , funcName ) == 0 ) {
					FARPROC originalFunc = GetProcAddress( GetModuleHandleA( dllName ) , funcName );
					if ( originalFunc && ( FARPROC ) thunkIAT->u1.Function != originalFunc ) {
						//std::cout << "IAT Hook detectado na função: " << funcName << std::endl;
						return true;
					}
				}
				thunkILT++;
				thunkIAT++;
			}
		}
		importDesc++;
	}
	return false;
}

bool DetectEATHook( HMODULE module , const char * funcName ) {
	FARPROC actualAddress = GetProcAddress( module , funcName );
	if ( !actualAddress ) return false;

	PIMAGE_DOS_HEADER dosHeader = ( PIMAGE_DOS_HEADER ) module;
	PIMAGE_NT_HEADERS ntHeaders = ( PIMAGE_NT_HEADERS ) ( ( BYTE * ) module + dosHeader->e_lfanew );

	// Verifica se o endereço exportado está dentro da seção .text do módulo
	DWORD textSectionStart = ntHeaders->OptionalHeader.BaseOfCode;
	DWORD textSectionEnd = textSectionStart + ntHeaders->OptionalHeader.SizeOfCode;

	DWORD funcOffset = ( DWORD ) ( ( BYTE * ) actualAddress - ( BYTE * ) module );
	if ( funcOffset < textSectionStart || funcOffset > textSectionEnd ) {
		std::cout << "EAT Hook detectado na função: " << funcName << std::endl;
		return true;
	}
	return false;
}

void Detections::CheckThreads( ) {
	DWORD currentProcessId = GetCurrentProcessId( );
	HANDLE hThreadSnap = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD , 0 );

	if ( hThreadSnap == INVALID_HANDLE_VALUE ) {
		std::cerr << "Falha ao capturar snapshot das threads." << std::endl;
		return;
	}

	// Pegar os módulos (DLLs e EXEs) carregados no processo
	HMODULE hMods[ 1024 ];
	HANDLE hProcess = GetCurrentProcess( );
	DWORD cbNeeded;

	if ( !EnumProcessModules( hProcess , hMods , sizeof( hMods ) , &cbNeeded ) ) {
		std::cerr << "Falha ao enumerar módulos carregados." << std::endl;
		CloseHandle( hThreadSnap );
		return;
	}

	THREADENTRY32 te32;
	te32.dwSize = sizeof( THREADENTRY32 );

	if ( !Thread32First( hThreadSnap , &te32 ) ) {
		std::cerr << "Falha ao pegar a primeira thread." << std::endl;
		CloseHandle( hThreadSnap );
		return;
	}

	do {
		if ( te32.th32OwnerProcessID == currentProcessId ) {
			HANDLE hThread = OpenThread( THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT , FALSE , te32.th32ThreadID );
			if ( hThread == NULL ) {
				std::cerr << "Falha ao abrir a thread: " << te32.th32ThreadID << std::endl;
				continue;
			}

			// Capturar o contexto da thread para pegar o endereço de instrução
			CONTEXT ctx;
			ctx.ContextFlags = CONTEXT_CONTROL;
			if ( GetThreadContext( hThread , &ctx ) ) {
				// Endereço de instrução atual (EIP no x86, RIP no x64)
				DWORD64 instructionAddress = ctx.Rip;
				bool isInModule = false;

				// Verificar se o endereço está dentro de um dos módulos carregados (DLLs de terceiros)
				for ( int i = 0; i < ( cbNeeded / sizeof( HMODULE ) ); i++ ) {
					MODULEINFO modInfo;
					if ( GetModuleInformation( hProcess , hMods[ i ] , &modInfo , sizeof( modInfo ) ) ) {
						DWORD64 modBase = ( DWORD64 ) modInfo.lpBaseOfDll;
						DWORD64 modEnd = modBase + modInfo.SizeOfImage;

						if ( instructionAddress >= modBase && instructionAddress <= modEnd ) {
							isInModule = true;
							break;
						}
					}
				}

				if ( !isInModule ) {
					std::cout << "Thread ID: " << te32.th32ThreadID << " NÃO está associada a um módulo carregado." << std::endl;
				}
			}
			CloseHandle( hThread );
		}
	} while ( Thread32Next( hThreadSnap , &te32 ) );

	CloseHandle( hThreadSnap );
}

// Método para injetar um processo
bool Detections::InjectProcess( DWORD processId ) {
	// Pegar o nome do executável
	char exePath[ MAX_PATH ];
	GetModuleFileNameA( NULL , exePath , MAX_PATH );
	std::string exePathStr( exePath );

	auto find = this->InjectedProcesses.find( processId );

	if ( find != this->InjectedProcesses.end( ) ) {
		return false;
	}

	std::string filename = xorstr_( "windows.dll" );
	if ( Utils::Get( ).ExistsFile( filename ) ) {
		this->InjectedProcesses[ processId ] = true;

		if ( Injector::Get( ).Inject( filename , processId ) == 1 )
			return true;
	}
	else {
		Utils::Get( ).WarnMessage( YELLOW , xorstr_( "!" ) , xorstr_( "Failed to find buffer" ) , LIGHT_GREEN );
	}

	return false;
}

// Método para remover a injeção de um processo (opcional)
void Detections::RemoveInjection( DWORD processId ) {

}

void Detections::CheckInjectedProcesses( ) {
	for ( auto it = InjectedProcesses.begin( ); it != InjectedProcesses.end( ); ) {
		// Condition: Erase elements with values greater than 20
		if ( !Mem::Get( ).IsPIDRunning( it->first ) ) {
			it = InjectedProcesses.erase( it );
		}
		else
			it++;
	}
}

void Detections::CheckHandles( ) {
	Utils::Get( ).WarnMessage( GREEN , xorstr_( "-" ) , xorstr_( "Handle scanning started" ) , LIGHT_GREEN );

	std::vector<SYSTEM_HANDLE> OpenHandles = Mem::Get( ).GetHandlesForProcess( GetCurrentProcessId( ) );
	if ( OpenHandles.empty( ) ) {
		std::cout << "[AEGIS] Didn't found open handles!\n";
		return;
	}
	for ( const SYSTEM_HANDLE handle : OpenHandles ) {
		this->m_healthy = true;
		if ( Mem::Get( ).ProcessIsOnSystemFolder( handle.ProcessId ) )
			continue;

		std::string ProcessName = Mem::Get( ).GetProcessName( handle.ProcessId );

		if ( ProcessName == "aegis.exe" || ProcessName == "server.exe" )
			continue;

		HANDLE hProcess = Mem::Get( ).GetProcessHandle( handle.ProcessId );

		if ( hProcess == NULL )
			continue;

		if ( !Mem::Get( ).VerifySignature( hProcess ) ) {
			//processos nao assinados
			BOOL isWow64 = FALSE;
			bool SystemProcess = Mem::Get( ).IsSystemProcess( hProcess );

			IsWow64Process( hProcess , &isWow64 );

			if ( !isWow64 && !SystemProcess ) {
				//64BIT Process
				Utils::Get( ).WarnMessage( YELLOW , xorstr_( "HANDLE" ) , Mem::Get( ).GetProcessName( handle.ProcessId ) + xorstr_( " [" ) + std::to_string( handle.ProcessId ) + xorstr_( "]" ) , RED );

				if ( InjectProcess( handle.ProcessId ) ) {
					Utils::Get( ).WarnMessage( YELLOW , xorstr_( "INJECTION" ) , xorstr_( "Sucessfully injected in process!" ) , LIGHT_WHITE );
				}
			}
		}

		CloseHandle( hProcess );
	}

	Utils::Get( ).WarnMessage( GREEN , xorstr_( "-" ) , xorstr_( "Handle scanning ended" ) , LIGHT_GREEN );
}

bool DetectInlineHook( FARPROC func , const BYTE * originalBytes , SIZE_T length ) {
	BYTE currentBytes[ 16 ];
	SIZE_T bytesRead;

	if ( ReadProcessMemory( GetCurrentProcess( ) , func , currentBytes , length , &bytesRead ) && bytesRead == length ) {
		// Compara os bytes da função com os bytes originais
		if ( memcmp( currentBytes , originalBytes , length ) != 0 ) {
			std::cout << "Inline Hook detectado!" << std::endl;
			return true;
		}
	}
	return false;
}

void Detections::KeepThreadAlive( ) {
	int Times = 0;
	while ( Times < 15 ) {
		this->m_healthy = true;
		std::this_thread::sleep_for( std::chrono::milliseconds( 1800 ) );
	}
}

void Detections::threadFunction( ) {
	Utils::Get( ).WarnMessage( LIGHT_BLUE , xorstr_( "detections" ) , xorstr_( "Sucessfully attached" ) , WHITE );

	while ( m_running ) {
		this->m_healthy = true;
		this->CheckInjectedProcesses( );
		this->CheckHandles( );
		this->CheckThreads( );

		/*if ( DetectEATHook( GetModuleHandle( "user32.dll" ) , "MessageBoxA" ) ) {
			std::cerr << "EAT Hook detectado!" << std::endl;
		}
		else {
			std::cout << "Nenhum EAT Hook detectado." << std::endl;
		}

		if ( DetectIATHook( GetModuleHandle( NULL ) , "MessageBoxA" , "user32.dll" ) ) {
			std::cerr << "IAT Hook detectado!" << std::endl;
		}
		else {
			std::cout << "Nenhum IAT Hook detectado." << std::endl;
		}*/

		std::thread( &Detections::KeepThreadAlive , this ).detach( );

		std::this_thread::sleep_for( std::chrono::seconds( 30 ) );
	}
}