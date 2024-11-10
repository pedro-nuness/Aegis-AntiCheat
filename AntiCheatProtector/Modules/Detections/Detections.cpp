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
#include "../../Systems/Memory/memory.h"
#include "../../Systems/Utils/xorstr.h"
#include "../../Systems/Injection/Injection.h"
#include "../../Systems/LogSystem/Log.h"

Detections::Detections( ) {}

Detections::~Detections( ) {}

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
	std::cout << "[detections] resetting thread!\n";
	if ( m_thread.joinable( ) ) {
		m_thread.join( );
	}
	start( );
}

void Detections::requestupdate( ) {
	this->m_healthy = false;
}

// Função de detecção de permissões suspeitas na memória
void Detections::DetectMemoryPermissions( ) {
	SYSTEM_INFO sysInfo;
	GetSystemInfo( &sysInfo );

	MEMORY_BASIC_INFORMATION memInfo;
	DWORD_PTR address = ( DWORD_PTR ) sysInfo.lpMinimumApplicationAddress;

	while ( address < ( DWORD_PTR ) sysInfo.lpMaximumApplicationAddress ) {
		if ( VirtualQuery( ( LPCVOID ) address , &memInfo , sizeof( memInfo ) ) == sizeof( memInfo ) ) {
			if ( memInfo.State == MEM_COMMIT && ( memInfo.Type == MEM_PRIVATE || memInfo.Type == MEM_IMAGE ) ) {
				if ( memInfo.Protect == PAGE_EXECUTE_READWRITE || memInfo.Protect == PAGE_EXECUTE_WRITECOPY ) {
					Utils::Get( ).WarnMessage( YELLOW , xorstr_( "DETECTION" ) , xorstr_( "Area de memoria com permissoes suspeitas detectada" ) , LIGHT_RED );
				}
			}
			address += memInfo.RegionSize;
		}
	}
}

// Remover injeção de um processo (opcional)
void Detections::RemoveInjection( DWORD processId ) {}

// Verifica processos injetados
void Detections::CheckInjectedProcesses( ) {
	for ( auto it = InjectedProcesses.begin( ); it != InjectedProcesses.end( );) {
		if ( !Mem::Get( ).IsPIDRunning( it->first ) ) {
			it = InjectedProcesses.erase( it );
		}
		else
			it++;
	}
}

// Verifica handles suspeitos
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
			BOOL isWow64 = FALSE;
			bool SystemProcess = Mem::Get( ).IsSystemProcess( hProcess );

			IsWow64Process( hProcess , &isWow64 );

			if ( !isWow64 && !SystemProcess ) {
				Utils::Get( ).WarnMessage( YELLOW , xorstr_( "HANDLE" ) , Mem::Get( ).GetProcessName( handle.ProcessId ) + xorstr_( " [" ) + std::to_string( handle.ProcessId ) + xorstr_( "]" ) , RED );

				if ( InjectProcess( handle.ProcessId ) ) {
					Utils::Get( ).WarnMessage( YELLOW , xorstr_( "INJECTION" ) , xorstr_( "Successfully injected in process!" ) , LIGHT_WHITE );
				}
			}
		}
		CloseHandle( hProcess );
	}
}

void CheckThreadsForSuspiciousContext( DWORD processID ) {
	HANDLE hThreadSnap = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD , 0 );
	if ( hThreadSnap == INVALID_HANDLE_VALUE ) {
		return;
	}

	THREADENTRY32 te32;
	te32.dwSize = sizeof( THREADENTRY32 );

	if ( !Thread32First( hThreadSnap , &te32 ) ) {
		CloseHandle( hThreadSnap );
		return;
	}
	do {
		if ( te32.th32OwnerProcessID == processID ) {
			HANDLE hThread = OpenThread( THREAD_ALL_ACCESS , FALSE , te32.th32ThreadID );
			if ( hThread ) {
				CONTEXT ctx;
				ctx.ContextFlags = CONTEXT_CONTROL;

				if ( GetThreadContext( hThread , &ctx ) ) {
					// Verifique se o endereço EIP/RIP está em uma região válida do processo
					MEMORY_BASIC_INFORMATION mbi;
					if ( VirtualQueryEx( GetCurrentProcess( ) , ( LPCVOID ) ctx.Rip , &mbi , sizeof( mbi ) ) ) {
						if ( mbi.Type == MEM_PRIVATE && ( mbi.Protect & PAGE_EXECUTE_READWRITE ) ) {
							std::cout << "Suspicious thread context at address: " << std::hex << ctx.Rip << std::endl;
						}
					}
				}
				CloseHandle( hThread );
			}
		}
	} while ( Thread32Next( hThreadSnap , &te32 ) );

	CloseHandle( hThreadSnap );
}

// Função de detecção de módulos desconhecidos injetados no processo
void Detections::DetectUnknownModules( ) {
	HANDLE hProcess = GetCurrentProcess( );
	HMODULE hMods[ 1024 ];
	DWORD cbNeeded;
	if ( EnumProcessModules( hProcess , hMods , sizeof( hMods ) , &cbNeeded ) ) {
		for ( unsigned int i = 0; i < ( cbNeeded / sizeof( HMODULE ) ); i++ ) {
			char moduleName[ MAX_PATH ];
			if ( GetModuleFileNameExA( hProcess , hMods[ i ] , moduleName , sizeof( moduleName ) / sizeof( char ) ) ) {
				if ( !Mem::Get( ).VerifyFileSignature( moduleName ) ) {
					Utils::Get( ).WarnMessage( YELLOW , xorstr_( "DETECTION" ) , xorstr_( "Modulo desconhecido e nao assinado detectado: " ) + (std::string)moduleName , LIGHT_RED );
				}
			}
		}
	}
}

// Verifica se funções de sistema críticas foram redirecionadas
bool Detections::CheckCriticalFunctionRedirects( std::string funcName ) {
	HMODULE hKernel32 = GetModuleHandleA( "kernel32.dll" );
	FARPROC funcAddr = GetProcAddress( hKernel32 , funcName.c_str( ) );

	if ( funcAddr != nullptr ) {
		MEMORY_BASIC_INFORMATION mbi;
		if ( VirtualQuery( funcAddr , &mbi , sizeof( mbi ) ) && mbi.State == MEM_COMMIT ) {
			if ( mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY ) {
				Utils::Get( ).WarnMessage( YELLOW , xorstr_( "DETECTION" ) , xorstr_( "Redirecionamento em funcao critica: " ) + funcName , LIGHT_RED );
				return true;
			}
		}
	}
	return false;
}

// Função de verificação de trampolins (hooks com saltos)
bool Detections::DetectTrampolines( FARPROC func , const BYTE * expectedBytes , SIZE_T length ) {
	BYTE currentBytes[ 16 ];
	SIZE_T bytesRead;

	if ( ReadProcessMemory( GetCurrentProcess( ) , func , currentBytes , length , &bytesRead ) && bytesRead == length ) {
		if ( memcmp( currentBytes , expectedBytes , length ) != 0 ) {
			Utils::Get( ).WarnMessage( YELLOW , xorstr_( "DETECTION" ) , xorstr_( "Possivel trampolin encontrado na funcao em" )  , LIGHT_RED );
			return true;
		}
	}
	return false;
}

// Verifica módulos DLL carregados dinamicamente que não pertencem ao sistema
void Detections::CheckDynamicModules( ) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE , GetCurrentProcessId( ) );
	if ( hSnapshot == INVALID_HANDLE_VALUE ) return;

	MODULEENTRY32 me32;
	me32.dwSize = sizeof( MODULEENTRY32 );

	if ( Module32First( hSnapshot , &me32 ) ) {
		do {
			std::string modulePath = me32.szExePath;
			if ( !Mem::Get( ).VerifyFileSignature( modulePath ) ) {
				Utils::Get( ).WarnMessage(  YELLOW , xorstr_( "DETECTION" ), xorstr_( "Modulo dinamico suspeito detectado: " ) + modulePath , LIGHT_RED );
			}
		} while ( Module32Next( hSnapshot , &me32 ) );
	}
	CloseHandle( hSnapshot );
}

// Função de verificação principal que chama todas as detecções
void Detections::RunDetections( ) {
	//DetectMemoryPermissions( );
	// DetectUnknownModules( );
	CheckCriticalFunctionRedirects( xorstr_("LoadLibraryA") );
	CheckCriticalFunctionRedirects( xorstr_("CreateRemoteThread") );
	CheckThreadsForSuspiciousContext( GetCurrentProcessId() );

	//CheckDynamicModules( );
}

// Verifica threads suspeitas
void Detections::CheckThreads( ) {
	DWORD currentProcessId = GetCurrentProcessId( );
	HANDLE hThreadSnap = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD , 0 );

	if ( hThreadSnap == INVALID_HANDLE_VALUE ) {
		return;
	}

	HMODULE hMods[ 1024 ];
	HANDLE hProcess = GetCurrentProcess( );
	DWORD cbNeeded;

	if ( !EnumProcessModules( hProcess , hMods , sizeof( hMods ) , &cbNeeded ) ) {
		CloseHandle( hThreadSnap );
		return;
	}

	THREADENTRY32 te32;
	te32.dwSize = sizeof( THREADENTRY32 );

	if ( !Thread32First( hThreadSnap , &te32 ) ) {
		CloseHandle( hThreadSnap );
		return;
	}

	do {
		if ( te32.th32OwnerProcessID == currentProcessId ) {
			HANDLE hThread = OpenThread( THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT , FALSE , te32.th32ThreadID );
			if ( hThread == NULL ) {
				continue;
			}

			CONTEXT ctx;
			ctx.ContextFlags = CONTEXT_CONTROL;
			if ( GetThreadContext( hThread , &ctx ) ) {
				DWORD64 instructionAddress = ctx.Rip;
				bool isInModule = false;

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
					Utils::Get( ).WarnMessage( YELLOW , xorstr_( "DETECTION" ) , xorstr_( "Thread ID nao acossiado a modulo carregado: " ) + te32.th32ThreadID , LIGHT_RED );
				}
			}
			CloseHandle( hThread );
		}
	} while ( Thread32Next( hThreadSnap , &te32 ) );

	CloseHandle( hThreadSnap );
}

// Método de injeção
bool Detections::InjectProcess( DWORD processId ) {
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

// Função do thread principal do anti-cheat
void Detections::threadFunction( ) {
	while ( m_running ) {
		this->m_healthy = true;
		RunDetections( );
		CheckThreads( );
		CheckInjectedProcesses( );
		CheckHandles( );
		std::this_thread::sleep_for( std::chrono::seconds( 10 ) );
	}
}
