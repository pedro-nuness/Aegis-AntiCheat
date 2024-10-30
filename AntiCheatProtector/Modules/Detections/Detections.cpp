#include "Detections.h"

#include <iostream>
#include <Windows.h>
#include <vector>
#include <thread>
#include <tlhelp32.h>
#include <psapi.h>
#include <unordered_map>

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

bool Detections::ScanProcessID( int pid ) {

}

bool Detections::ScanCurrentThreads( ) {


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

				// Verificar se o endereço está dentro de um dos módulos carregados (DLLs de terceiros)
				for ( int i = 0; i < ( cbNeeded / sizeof( HMODULE ) ); i++ ) {
					MODULEINFO modInfo;
					if ( GetModuleInformation( hProcess , hMods[ i ] , &modInfo , sizeof( modInfo ) ) ) {
						DWORD64 modBase = ( DWORD64 ) modInfo.lpBaseOfDll;
						DWORD64 modEnd = modBase + modInfo.SizeOfImage;

						if ( instructionAddress >= modBase && instructionAddress <= modEnd ) {
							TCHAR szModName[ MAX_PATH ];
							if ( GetModuleFileNameEx( hProcess , hMods[ i ] , szModName , sizeof( szModName ) / sizeof( TCHAR ) ) ) {
								//std::wcout << L"Thread ID: " << te32.th32ThreadID << L" executando no módulo: " << szModName << std::endl;
							}
						}
					}
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

	std::string Hash = xorstr_( "hash" );
	std::string filename = xorstr_( "windows.dll" );
	if ( Utils::Get( ).ExistsFile( filename ) ) {

		/*std::string FileHash = Mem::Get( ).GetFileHash( xorstr_( "scanner.dll" ) );
		if ( FileHash != Hash )
			LogSystem::Get( ).Log( xorstr_( "[000032] invalid file" ) );*/
		this->InjectedProcesses[ processId ] = true;

		if ( Injector::Get( ).Inject( filename , processId ) == 1 )
			return true;
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

	const std::vector<SYSTEM_HANDLE> OpenHandles = Mem::Get( ).GetHandlesForProcess( GetCurrentProcessId( ) );
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

		std::thread( &Detections::KeepThreadAlive , this ).detach( );

		std::this_thread::sleep_for( std::chrono::seconds( 30 ) );
	}
}