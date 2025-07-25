#include <iostream>
#include <Windows.h>
#include <string>
#include <thread>
#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <cassert>
#include <tlhelp32.h>
#include <filesystem>
#include <nlohmann/json.hpp>

#include "Modules/Triggers/Triggers.h"
#include "Modules/Communication/Communication.h"
#include "Modules/ThreadGuard/ThreadGuard.h"
#include "Modules/Detections/Detections.h"
#include "Modules/AntiDebugger/AntiDebugger.h"
#include "Modules/Listener/Listener.h"

#include "Systems/LogSystem/Log.h"
#include "Systems/Preventions/Preventions.h"
#include "Systems/Utils/utils.h"
#include "Systems/Utils/xorstr.h"
#include "Systems/Memory/memory.h"
#include "Systems/Monitoring/Monitoring.h"
#include "Systems/FileChecking/FileChecking.h"
#include "Systems/Hardware/hardware.h"
#include "Systems/LogSystem/File/File.h"
#include "Systems/Services/Services.h"

#include "Client/client.h"
#include "Globals/Globals.h"

#include "../../externals/minhook/MinHook.h"

using nlohmann::json;

namespace fs = std::filesystem;

#include <d3d11.h>
#include <dxgi.h>

#define IDR_DUMPERDLL 104
#define IDR_LIBCRYPTO 105
#define IDR_LIBSSL 106

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")

typedef HRESULT( __stdcall * Present_t )( IDXGISwapChain * pSwapChain , UINT SyncInterval , UINT Flags );
Present_t oPresent = nullptr;

ID3D11Device * pDevice;
ID3D11DeviceContext * pContext;

bool loadingScreenStarted = false;
bool loadingScreenEnded = false;
bool TempConnection = true;
std::vector<BYTE> lastFrameRegion;

bool FrameCentralMudou( BYTE * atual , BYTE * anterior , int larguraLinha , int larguraRegiao , int alturaRegiao , int tolerancia = 5 ) {
	int diferentes = 0;
	int totalPixels = larguraRegiao * alturaRegiao * 4; // 4 bytes por pixel (RGBA)

	for ( int y = 0; y < alturaRegiao; y++ ) {
		BYTE * linhaAtual = atual + y * larguraLinha;
		BYTE * linhaAnterior = anterior + y * larguraLinha;

		for ( int x = 0; x < larguraRegiao * 4; x++ ) {
			if ( abs( linhaAtual[ x ] - linhaAnterior[ x ] ) > tolerancia ) {
				diferentes++;
				if ( diferentes > 500 ) return true; // limite mínimo pra considerar que mudou
			}
		}
	}

	return false;
}

HRESULT __stdcall hkPresent( IDXGISwapChain * pSwapChain , UINT SyncInterval , UINT Flags ) {
	if ( !loadingScreenStarted ) {
		loadingScreenStarted = true;
		LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "loading screen started" ) , GREEN );
	}

	static bool init = false;
	static int largura = 0 , altura = 0;

	if ( !init ) {
		pSwapChain->GetDevice( __uuidof( ID3D11Device ) , ( void ** ) &pDevice );
		pDevice->GetImmediateContext( &pContext );
		init = true;
	}

	if ( !loadingScreenEnded ) {
		ID3D11Texture2D * backBuffer = nullptr;
		if ( SUCCEEDED( pSwapChain->GetBuffer( 0 , __uuidof( ID3D11Texture2D ) , ( void ** ) &backBuffer ) ) ) {
			D3D11_TEXTURE2D_DESC desc;
			backBuffer->GetDesc( &desc );

			largura = desc.Width;
			altura = desc.Height;

			D3D11_TEXTURE2D_DESC stagingDesc = desc;
			stagingDesc.Usage = D3D11_USAGE_STAGING;
			stagingDesc.BindFlags = 0;
			stagingDesc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
			stagingDesc.MiscFlags = 0;

			ID3D11Texture2D * stagingTexture = nullptr;
			if ( SUCCEEDED( pDevice->CreateTexture2D( &stagingDesc , nullptr , &stagingTexture ) ) ) {
				pContext->CopyResource( stagingTexture , backBuffer );

				D3D11_MAPPED_SUBRESOURCE mapped;
				if ( SUCCEEDED( pContext->Map( stagingTexture , 0 , D3D11_MAP_READ , 0 , &mapped ) ) ) {
					// Define região central (ex: 100x100 px)
					const int regiaoLargura = 100;
					const int regiaoAltura = 100;
					const int startX = ( largura / 2 ) - ( regiaoLargura / 2 );
					const int startY = ( altura / 2 ) - ( regiaoAltura / 2 );

					std::vector<BYTE> currentRegion( regiaoLargura * regiaoAltura * 4 );

					for ( int y = 0; y < regiaoAltura; y++ ) {
						BYTE * src = reinterpret_cast< BYTE * >( mapped.pData ) + ( startY + y ) * mapped.RowPitch + startX * 4;
						memcpy( &currentRegion[ y * regiaoLargura * 4 ] , src , regiaoLargura * 4 );
					}

					if ( !lastFrameRegion.empty( ) ) {
						if ( FrameCentralMudou( currentRegion.data( ) , lastFrameRegion.data( ) , regiaoLargura * 4 , regiaoLargura , regiaoAltura ) ) {
							loadingScreenEnded = true;
							std::this_thread::sleep_for( std::chrono::seconds( 5 ) );
						}
					}

					lastFrameRegion = currentRegion;
					pContext->Unmap( stagingTexture , 0 );
				}

				stagingTexture->Release( );
			}

			backBuffer->Release( );
		}
	}

	return oPresent( pSwapChain , SyncInterval , Flags );
}

bool HookPresent( ) {

	LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "Waiting game window" ) , GREEN );
	while ( !FindWindowA( NULL, xorstr_("DayZ") ) ) {
		std::this_thread::sleep_for( std::chrono::seconds( 1 ) );
	}

	HWND window = GetForegroundWindow( );
	if ( !window ) {
		LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "can't get foreground window!" ) , RED );
		return false;
	}

	DXGI_SWAP_CHAIN_DESC scd = {};
	scd.BufferCount = 1;
	scd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
	scd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
	scd.OutputWindow = window;// Qualquer janela
	scd.SampleDesc.Count = 1;
	scd.Windowed = TRUE;
	scd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

	D3D_FEATURE_LEVEL featureLevel;
	ID3D11Device * pDevice = nullptr;
	ID3D11DeviceContext * pContext = nullptr;
	IDXGISwapChain * pSwapChain = nullptr;

	if ( D3D11CreateDeviceAndSwapChain( nullptr , D3D_DRIVER_TYPE_HARDWARE , nullptr , 0 , nullptr ,
		0 , D3D11_SDK_VERSION , &scd , &pSwapChain , &pDevice , &featureLevel , &pContext ) != S_OK ) {
		LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "Failed to create d3d11 Device" ) , GREEN );
		return false;
	}

	void ** pVTable = *reinterpret_cast< void *** >( pSwapChain ); // VTable do SwapChain
	void * pPresent = pVTable[ 8 ]; // Index 8 = Present()


	if ( pPresent != nullptr && pSwapChain != nullptr) {
		MH_CreateHook( pPresent , &hkPresent , reinterpret_cast< void ** >( &oPresent ) );
		MH_EnableHook( pPresent );
		LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "pPresent hooked!" ) , GREEN );
	}
	else {
		LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "Failed to find pPresent!" ) , RED );
		return false;
	}

	// Cleanup
	pSwapChain->Release( );
	pDevice->Release( );
	pContext->Release( );

	return true;
}

void * LoadInternalResource( DWORD * buffer, int resourceID, LPSTR type ) {
	if ( _globals.dllModule == NULL ) {
		LogSystem::Get( ).ConsoleLog( _MAIN, std::to_string( resourceID ) + xorstr_( ": Error gettind dll module" ) , RED );
		return nullptr;
	}

	HRSRC hResInfo = FindResourceA( _globals.dllModule , MAKEINTRESOURCE( resourceID ) , type );
	if ( hResInfo == NULL ) {
		LogSystem::Get( ).ConsoleLog( _MAIN , std::to_string( resourceID ) + xorstr_( ": Error locating resources" ) , RED );
		return nullptr;
	}

	DWORD resourceSize = SizeofResource( _globals.dllModule , hResInfo );
	if ( resourceSize == 0 ) {
		LogSystem::Get( ).ConsoleLog( _MAIN , std::to_string( resourceID ) + xorstr_( ": Error gettind resource size" ) , RED );
		return nullptr;
	}

	HGLOBAL hResData = LoadResource( _globals.dllModule , hResInfo );
	if ( hResData == NULL ) {
		LogSystem::Get( ).ConsoleLog( _MAIN , std::to_string( resourceID ) + xorstr_( ": Error loading resource" ) , RED );
		return nullptr;
	}

	void * pResData = LockResource( hResData );
	if ( pResData == NULL ) {
		LogSystem::Get( ).ConsoleLog( _MAIN , std::to_string( resourceID ) + xorstr_( ": Error locking resource" ) , RED );
		return nullptr;
	}

	*buffer = resourceSize;

	return pResData;
}

bool LoadLibraryWithMemory(char* data, DWORD size, std::string name = "" ) {
	std::string filename = ( name.empty( ) ? Utils::Get( ).GetRandomWord( 32 ) + xorstr_( ".dll" ) : name);

	// Pega caminho da pasta TEMP
	char tempPath[ MAX_PATH ];
	if ( !GetTempPathA( MAX_PATH , tempPath ) ) return "";

	std::string fullPath = std::string( tempPath ) + filename;

	// Salvar a DLL extraída em um arquivo temporário
	std::ofstream outFile( fullPath , std::ios::binary );
	if ( outFile ) {
		outFile.write( data, size);
		outFile.close( );

		// Carregar a DLL usando LoadLibrary
		HMODULE hModule = LoadLibrary( fullPath.c_str() );

		if ( !fs::remove( fullPath.c_str( ) ) ) {
			LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "Couldnt delete library" ) , RED );
		}

		if ( hModule ) {
			return true;
		}
	}
	else {
		LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "Couldnt save library" ) , RED );
		return false;
	}

	return false;
}


bool LoadAntiCheatResources( ) {
	{
		DWORD dumperSize = 0;
		void * dumperDll = LoadInternalResource( &dumperSize , IDR_DUMPERDLL , RT_RCDATA );
		if ( dumperDll == nullptr ) {
			return false;
		}
		_globals.encryptedDumper = std::vector<uint8_t>( ( uint8_t * ) dumperDll , ( uint8_t * ) dumperDll + dumperSize );
	}

	std::string teste = Utils::Get().GenerateStringHash( "teste" );

	LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "Resources loaded succesfully" ) , GREEN );

	return true;
}

void Startup( ) {
	Communication CommunicationEvent( _globals.OriginalProcess , _globals.ProtectProcess );
	Triggers TriggerEvent( _globals.OriginalProcess , _globals.ProtectProcess );
	AntiDebugger AntiDbg;
	Listener ListenEvent;

	Detections * detection = ( Detections * ) _globals.DetectionsPointer;

	detection->SetupPid( _globals.OriginalProcess , _globals.ProtectProcess );


	//threads holder
	std::vector<std::pair<ThreadHolder * , int>> threads = {
		std::make_pair( detection, DETECTIONS ),
		std::make_pair( &AntiDbg, ANTIDEBUGGER ),
		std::make_pair( &TriggerEvent, TRIGGERS ) ,
		std::make_pair( &CommunicationEvent, COMMUNICATION ),
		std::make_pair( &ListenEvent,  LISTENER )
	};

	ThreadHolder::initializeThreadWaiter( );

	CommunicationEvent.start( );
	detection->start( );
	TriggerEvent.start( );
	AntiDbg.start( );
	ListenEvent.start( );

	detection->InitializeThreads( );

	ThreadGuard monitor( threads );
	_globals.GuardMonitorPointer = &monitor;

	_globals.TriggersPointer = &TriggerEvent;
	_globals.AntiDebuggerPointer = &AntiDbg;
	monitor.start( );

	std::this_thread::sleep_for( std::chrono::seconds( 5 ) );

	while ( !loadingScreenEnded ) {
		std::this_thread::sleep_for( std::chrono::seconds( 1 ) );
	}

	if ( !Preventions::Get( ).DeployLastBarrier( ) ) {
		LogSystem::Get( ).Error( xorstr_( "[401] Failed to deploy last barrier" ) , false );
		return;
	}

	while ( true ) {
		LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "ping" ) , GRAY );

		switch ( monitor.isRunning() ) {
		case THREAD_STATUS::INITIALIZATION_FAILED:
			LogSystem::Get( ).Error( xorstr_( "thread monitor thread initialization failed!" ), false);
			return;
			break;
		case THREAD_STATUS::TERMINATED:
			_client.SendPunishToServer(xorstr_( "thread monitor thread was found terminated! Abnormal execution" ) , CommunicationType::BAN );
			return;
			break;

		case THREAD_STATUS::SUSPENDED:
			_client.SendPunishToServer( xorstr_( "thread monitor thread was found suspended! Abnormal execution" ) , CommunicationType::BAN );
			return;
			break;
		}

		std::this_thread::sleep_for( std::chrono::seconds( 5 ) );
	}
}

DWORD GetParentProcessID( DWORD processID ) {
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof( PROCESSENTRY32 );

	// Create a snapshot of all processes
	HANDLE snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS , 0 );
	if ( snapshot == INVALID_HANDLE_VALUE ) {
		return 0;
	}

	// Iterate through the processes to find the one with the matching process ID
	if ( Process32First( snapshot , &pe ) ) {
		do {
			if ( pe.th32ProcessID == processID ) {
				CloseHandle( snapshot );
				return pe.th32ParentProcessID;
			}
		} while ( Process32Next( snapshot , &pe ) );
	}

	CloseHandle( snapshot );
	return 0;
}

bool IsProcessParent( DWORD processID , DWORD targetParentPID ) {
	DWORD parentPID = GetParentProcessID( processID );
	return parentPID == targetParentPID;
}

ULONGLONG FileTimeToULL( const FILETIME & ft ) {
	ULARGE_INTEGER li;
	li.LowPart = ft.dwLowDateTime;
	li.HighPart = ft.dwHighDateTime;
	return li.QuadPart;
}

double GetProcessUptimeSeconds( ) {
	FILETIME createTime , exitTime , kernelTime , userTime;

	if ( GetProcessTimes( GetCurrentProcess( ) , &createTime , &exitTime , &kernelTime , &userTime ) ) {
		FILETIME now;
		GetSystemTimeAsFileTime( &now );

		ULONGLONG now64 = FileTimeToULL( now );
		ULONGLONG create64 = FileTimeToULL( createTime );

		// Cada unidade do FILETIME representa 100 nanossegundos
		return ( now64 - create64 ) / 10000000.0; // converte para segundos
	}

	return -1.0;
}

bool OpenConsole( ) {

	AllocConsole( );
	if ( freopen( "CONOUT$" , "w" , stdout ) == nullptr ) {
		return false;
	}
	::ShowWindow( ::GetConsoleWindow( ) , SW_SHOW );

	return true;
}

void TempConnectionThread( ) {
	while ( TempConnection ) {
		if ( !_client.SendPingToServer( ) ) {
			LogSystem::Get( ).ConsoleLog(_MAIN, xorstr_("Can't send ping to server" ) , RED );
		}

		std::this_thread::sleep_for( std::chrono::seconds( 10 ) );
	}
}

DWORD WINAPI main( LPVOID lpParam ) {
	double StartupTime = GetProcessUptimeSeconds( );

	if ( StartupTime > 2 ) {
		LogSystem::Get( ).Error( xorstr_( "[401] Failed to start process" ) , false );
		return 1;
	}

	//Ignore errors caused in process
	SetErrorMode( SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX );

	if ( !Services::Get().IsRunningAsAdmin( ) ) {
		LogSystem::Get( ).MessageBoxError( xorstr_( "Process is not on admin mode!" ) , xorstr_( "Process is not on admin mode!" ) , false );
		return 1;
	}

	if ( !fs::exists( xorstr_( "ACLogs" ) ) )
		fs::create_directory( xorstr_( "ACLogs" ) );
	
	OpenConsole( );

	if ( MH_Initialize( ) != MH_OK ) {
		LogSystem::Get( ).Error(  xorstr_( "MinHook initialization failed!" ), false );
		return 1;
	}
	LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "minhook initialized" ) , GREEN );
	
	LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "Process startup Time:" ) + std::to_string( StartupTime ) , WHITE );

	if ( !Preventions::Get( ).DeployFirstBarrier( ) ) {
		LogSystem::Get( ).Error( xorstr_( "[401] Failed to deploy first barrier" ) , false );
		return 1;
	}

	if ( !LoadAntiCheatResources( ) ) {
		LogSystem::Get( ).Error( xorstr_( "[401] Failed to load resources" ) , false );
		return 1;
	}

	if ( !FileChecking::Get( ).ValidateFiles( ) ) {
		LogSystem::Get( ).Error( xorstr_( "[401] Can't validate files" ) , false );
		return 1;
	}

	Utils::Get( ).waitModule( xorstr_( "ntdll" ) );

	Detections DetectionEvent;

	_globals.GameName = xorstr_( "DayZ_x64.exe" );
	_globals.DetectionsPointer = &DetectionEvent;
	_globals.SelfID = ::_getpid( );
	DWORD ParentProcessId = GetParentProcessID( _globals.SelfID ); // Get the parent process ID
	if ( !ParentProcessId ) {
		LogSystem::Get( ).Error( xorstr_( "[401] Initialization failed no parent" ) , false );
		return 1;
	}
	_globals.OriginalProcess = ParentProcessId;
	LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "Parent: " ) + Mem::Get( ).GetProcessName( ParentProcessId ) , GRAY );

	//Request MB and Disk ID
	if ( !hardware::Get( ).GenerateInitialCache( ) ) {
		LogSystem::Get( ).Error( xorstr_( "[401] Failed to generate initial hardware cache" ) , false );
		return 1;
	}

	if ( !hardware::Get( ).EndCacheGeneration( ) ) {
		LogSystem::Get( ).Error( xorstr_( "[401] Failed to end hardware cache" ) , false );
		return 1;
	}
	if ( !HookPresent( ) ) {
		LogSystem::Get( ).Error( xorstr_( "Failed to hook directx" ) , false );
		return 1;
	}

	while(!loadingScreenStarted ) {
		std::this_thread::sleep_for( std::chrono::seconds( 1 ) );
	}

	if ( !Preventions::Get( ).DeployMidBarrier( ) ) {
		LogSystem::Get( ).Error( xorstr_( "[401] Failed to deploy mid barrier" ) , false );
		return 1;
	}

	if ( !_client.SendPingToServer( ) ) {
		LogSystem::Get( ).Error( xorstr_( "[401] Can't connect to server" ) , false );
	}

	Startup( );
idle:
	int MaxIdle = 3;
	for ( int i = 0; i <= MaxIdle; i++ ) {
		LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "idle" ) , GRAY );
		std::this_thread::sleep_for( std::chrono::seconds( 5 ) );
	}

	return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule ,
	DWORD  ul_reason_for_call ,
	LPVOID lpReserved )
{
	_globals.dllModule = hModule;

	switch ( ul_reason_for_call )
	{
	case DLL_PROCESS_ATTACH:
		// Cria a thread quando a DLL é carregada
		CreateThread( NULL , 0 , main , NULL , 0 , NULL );
		break;
	case DLL_PROCESS_DETACH:
		// Finalização, se necessário
		break;
	}
	return TRUE;
}