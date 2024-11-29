#include "Detections.h"

#include <iostream>
#include <Windows.h>
#include <vector>
#include <thread>
#include <tlhelp32.h>
#include <psapi.h>
#include <unordered_map>
#include <dbghelp.h>
#include <tlhelp32.h>
#include <fstream>


#pragma comment(lib, "dbghelp.lib")

#include "../../Systems/Utils/utils.h"
#include "../../Systems/Memory/memory.h"
#include "../../Systems/Utils/xorstr.h"
#include "../../Systems/Injection/Injection.h"
#include "../../Systems/LogSystem/Log.h"
#include "../../Systems/AntiTamper/Authentication.h"
#include "../../Client/client.h"


Detections::Detections( ) {}

Detections::~Detections( ) {}



bool Detections::isRunning( ) const {
	if ( this->ThreadObject->IsThreadSuspended( this->ThreadObject->GetHandle( ) ) ) {
		LogSystem::Get( ).Log( xorstr_( "Failed to run thread" ) );
	}

	if ( !this->ThreadObject->IsThreadRunning( this->ThreadObject->GetHandle( ) ) && !this->ThreadObject->IsShutdownSignalled( ) ) {

		LogSystem::Get( ).Log( xorstr_( "Failed to run thread" ) );
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

bool DoesProcessHaveOpenHandleTous( DWORD pid , std::vector <_SYSTEM_HANDLE> handles )
{
	if ( pid == 0 || pid == 4 ) //system idle process + system pids
		return false;

	for ( const auto & handle : handles )
	{
		if ( handle.ProcessId == pid && handle.ReferencingUs )
		{
			return true;
		}
	}

	return false;
}


bool SaveFirstFunctionBytes( const std::string & moduleName , const std::string & functionName , const std::string & outputFileName , size_t byteCount ) {
	// Obter o handle do módulo
	HMODULE hModule = GetModuleHandleA( moduleName.c_str( ) );
	if ( !hModule ) {
		std::cout << "Erro: Não foi possível encontrar o módulo: " << moduleName << std::endl;
		return false;
	}

	// Obter o endereço da função
	FARPROC funcAddress = GetProcAddress( hModule , functionName.c_str( ) );
	if ( !funcAddress ) {
		std::cout << "Erro: Não foi possível encontrar a função: " << functionName << std::endl;
		return false;
	}

	// Salvar os primeiros X bytes da função
	BYTE * start = reinterpret_cast< BYTE * >( funcAddress );

	std::ofstream outFile( outputFileName );
	if ( !outFile.is_open( ) ) {
		std::cout << "Erro: Não foi possível abrir o arquivo: " << outputFileName << std::endl;
		return false;
	}

	outFile << "unsigned char functionBytes[] = {";
	for ( size_t i = 0; i < byteCount; ++i ) {
		outFile << "0x" << std::hex << static_cast< int >( start[ i ] );
		if ( i < byteCount - 1 ) outFile << ", "; // Adiciona vírgula entre os bytes
	}
	outFile << "};" << std::endl;

	outFile.close( );
	std::cout << "Os primeiros " << byteCount << " bytes da função foram salvos em: " << outputFileName << std::endl;
	return true;
}



bool Detections::DoesFunctionAppearHooked( std::string moduleName , std::string functionName , const unsigned char * expectedBytes )
{
	if ( moduleName.empty( ) || functionName.empty( ) )
		return false;

	if ( !expectedBytes|| expectedBytes == nullptr ) {
		SaveFirstFunctionBytes( moduleName , functionName , functionName + xorstr_( ".txt" ) , 15 );
		return false;
	}

	bool FunctionPreambleHooked = false;

	HMODULE hMod = GetModuleHandleA( moduleName.c_str( ) );
	if ( hMod == NULL )
	{
		LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "Couldn't fetch module " ) + moduleName , RED );
		return false;
	}


	UINT64 AddressFunction = ( UINT64 ) GetProcAddress( hMod , functionName.c_str( ) );

	if ( AddressFunction == NULL )
	{
		LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "Couldn't fetch address of function " ) + functionName , RED );
		return FALSE;
	}

	bool FOUND_HOOK = false;

	unsigned char buffer[ sizeof( expectedBytes ) ];
	SIZE_T bytesRead;
	if ( ReadProcessMemory( GetCurrentProcess( ) , ( void * ) AddressFunction , buffer , sizeof( expectedBytes ) , &bytesRead ) ) {
		if ( memcmp( buffer , expectedBytes , sizeof( expectedBytes ) ) != 0 ) {
			FOUND_HOOK = TRUE;
		}
	}

	return FOUND_HOOK;
}


void Detections::CheckFunctions( ) {

	{
		unsigned char SENDfunctionBytes[ ] = {
		0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18
		};

		if ( this->DoesFunctionAppearHooked( xorstr_( "ws2_32.dll" ) , xorstr_( "send" ) , SENDfunctionBytes ) ) {
			AddDetection( FUNCTION_HOOKED , DetectionStruct( xorstr_( "ws2_32.dll:send() hooked" ) , SUSPECT ) );
			LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "ws2_32.dll:send() hooked" ) , RED );
		}
	}

	{
		unsigned char RECVfunctionBytes[ ] = {
	0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10, 0x44, 0x89, 0x4C, 0x24, 0x20
		};

		if ( this->DoesFunctionAppearHooked( xorstr_( "ws2_32.dll" ) , xorstr_( "recv" ) , RECVfunctionBytes ) ) {
			AddDetection( FUNCTION_HOOKED , DetectionStruct( xorstr_( "ws2_32.dll:recv() hooked" ) , SUSPECT ) );
			LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "ws2_32.dll:recv() hooked" ) , RED );
		}
	}

	{

	/*	std::vector<std::tuple<std::string , std::string , const unsigned char *>> functionsToCheck = {
		{"dxgi.dll", "IDXGISwapChain::Present", nullptr},
		{"dxgi.dll", "IDXGISwapChain::ResizeBuffers", nullptr},
		{"d3d11.dll", "ID3D11Device::CreateRenderTargetView", nullptr},
		{"d3d11.dll", "ID3D11DeviceContext::Draw", nullptr},
		{"d3d11.dll", "ID3D11DeviceContext::DrawIndexed", nullptr},
		{"d3d11.dll", "ID3D11Device::CreateBuffer", nullptr},
		{"d3d11.dll", "ID3D11Device::CreateShaderResourceView", nullptr},
		};

		for ( const auto & [moduleName , functionName , expectedBytes] : functionsToCheck ) {
			bool isHooked = DoesFunctionAppearHooked( moduleName , functionName , expectedBytes );
			if ( isHooked ) {
				LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "Hook detected in function: " ) + functionName , RED );
			}
		}*/
	}
}


// Verifica handles suspeitos
void Detections::CheckHandles( ) {
	std::vector<_SYSTEM_HANDLE> handles = Mem::Handle::Get( ).DetectOpenHandlesToProcess( );

	for ( auto & handle : handles )
	{
		if ( DoesProcessHaveOpenHandleTous( handle.ProcessId , handles ) )
		{
			std::string ProcessPath = Mem::Get( ).GetProcessExecutablePath( handle.ProcessId );

			//if ( !Authentication::Get( ).HasSignature( ProcessPath ) ) {
			//LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "Process " ) + Mem::Get( ).GetProcessExecutablePath( handle.ProcessId ) + xorstr_( " has open handle to us!" ) , RED );
			//}

			/*
			* System processes
			Process C:\Windows\System32\svchost.exe has open handle to us!
			Process C:\Windows\System32\conhost.exe has open handle to us!
			  Process D:\Program Files (x86)\Steam\steam.exe
			  C:\\Windows\\System32\\audiodg.exe
			  C:\\Windows\\System32\\lsass.exe
			*/

			if ( !strcmp( ProcessPath.c_str() , xorstr_( "C:\\Windows\\System32\\audiodg.exe" ) ) ) {
				continue;
			}

			if ( !strcmp( ProcessPath.c_str( ) , xorstr_( "C:\\Windows\\System32\\svchost.exe" ) ) ) {
				continue;
			}

			if ( !strcmp( ProcessPath.c_str( ) , xorstr_( "C:\\Windows\\System32\\lsass.exe" ) ) ) {
				continue;
			}

			if ( !strcmp( ProcessPath.c_str( ) , xorstr_( "C:\\Windows\\System32\\conhost.exe" ) ) )
				continue;

			HANDLE processHandle = OpenProcess( PROCESS_DUP_HANDLE , FALSE , handle.ProcessId );

			if ( processHandle )
			{
				HANDLE duplicatedHandle = INVALID_HANDLE_VALUE;

				if ( DuplicateHandle( processHandle , ( HANDLE ) handle.Handle , GetCurrentProcess( ) , &duplicatedHandle , 0 , FALSE , DUPLICATE_SAME_ACCESS ) )
				{
					if ( Mem::Handle::Get( ).CheckDangerousPermissions( duplicatedHandle, nullptr ) ) {
						LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "Process " ) + Mem::Get( ).GetProcessExecutablePath( handle.ProcessId ) + xorstr_( " has open handle to us!" ) , RED );

						if ( InjectProcess( handle.ProcessId ) ) {
							LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "Dumpped nigga :)") , GREEN );
						}
					}
					else
						LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "Process " ) + Mem::Get( ).GetProcessExecutablePath( handle.ProcessId ) + xorstr_( " has open handle to us!" ) , YELLOW );
				

					if ( duplicatedHandle != INVALID_HANDLE_VALUE )
						CloseHandle( duplicatedHandle );
				}

				CloseHandle( processHandle );
			}
			

			// AddDetection( OPENHANDLE_TO_US , DetectionStruct( ProcessPath , SUSPECT  );

			//LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "Process " ) + Mem::Get( ).GetProcessExecutablePath( handle.ProcessId ) + xorstr_( " has open handle to us!" ) , RED );
			//Logger::logfw( "UltimateAnticheat.log" , Detection , L"Process %s has open process handle to our process." , procName.c_str( ) );
			//foundHandle = TRUE;
			//continue;
		}
	}
}

void Detections::AddDetection( FLAG_DETECTION flag , DetectionStruct _detection ) {
	this->DetectedFlags.emplace_back( std::make_pair( flag , _detection ) );
}


std::string Detections::GenerateDetectionStatus( FLAG_DETECTION flag , DetectionStruct _detection ) {

	std::string _result = "";

	switch ( flag ) {
	case UNVERIFIED_DRIVER_RUNNING:
		_result += xorstr_( "** Unverified Driver Running on System**\n" );
		break;
	case UNVERIFIED_MODULE_LOADED:
		_result += xorstr_( "** Unverified Module Loaded **\n" );
		break;
	case SUSPECT_WINDOW_OPEN:
		_result += xorstr_( "** Suspect window open **\n" );
		break;
	case HIDE_FROM_CAPTURE_WINDOW:
		_result += xorstr_( "** Found window hiding from capture **\n" );
		break;
	case FUNCTION_HOOKED:
		_result += xorstr_( "** Found hook in function **\n" );
		break;
	case OPENHANDLE_TO_US:
		_result += xorstr_( "** Found open handle to our process **\n" );
		break;
	}

	_result += xorstr_( "`" ) + _detection.Log + xorstr_( "`\n" );

	return _result;
}


void Detections::DigestDetections( ) {
	if ( DetectedFlags.empty( ) ) {
		return;
	}

	if ( !DetectedFlags.empty( ) ) {
		/*
		* DIGEST DETECTION
		*/
		std::string FinalInfo = "";

		FinalInfo += xorstr_( "> AC FLAG detected\n\n" );

		bool Ban = false;

		for ( auto Detection : DetectedFlags ) {
			FinalInfo += this->GenerateDetectionStatus( Detection.first , Detection.second );
			if ( Detection.second._Status == DETECTED )
				Ban = true;
		}

		LogSystem::Get( ).ConsoleLog( _DETECTION , FinalInfo , Ban ? RED : YELLOW );

		client::Get( ).SendMessageToServer( FinalInfo , Ban ? BAN : WARN );
		LogSystem::Get( ).Log( xorstr_( "AC Flagged unsafe!" ) );
	}

	this->DetectedFlags.clear( );
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
		LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "Failed to find buffer" ) , LIGHT_GREEN );
	}

	return false;
}

// Função do thread principal do anti-cheat
void Detections::threadFunction( ) {
	bool m_running = true;

	while ( m_running ) {
		CheckInjectedProcesses( );
		CheckFunctions( );
		CheckHandles( );
		std::this_thread::sleep_for( std::chrono::seconds( 10 ) );
	}
}
