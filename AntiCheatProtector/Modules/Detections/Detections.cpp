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
#include <winternl.h>


Detections::Detections( ) {

	HMODULE hNtdll = GetModuleHandleA( xorstr_( "ntdll.dll" ) );
	if ( hNtdll != 0 ) //register DLL notifications callback 
	{
		_LdrRegisterDllNotification pLdrRegisterDllNotification = ( _LdrRegisterDllNotification ) GetProcAddress( hNtdll , xorstr_( "LdrRegisterDllNotification" ) );
		PVOID cookie;
		NTSTATUS status = pLdrRegisterDllNotification( 0 , ( PLDR_DLL_NOTIFICATION_FUNCTION ) OnDllNotification , this , &cookie );
	}
}


VOID CALLBACK Detections::OnDllNotification( ULONG NotificationReason , const PLDR_DLL_NOTIFICATION_DATA NotificationData , PVOID Context )
{
	Detections * Monitor = reinterpret_cast< Detections * >( Context );

	if ( NotificationReason == LDR_DLL_NOTIFICATION_REASON_LOADED )
	{
		LPCWSTR FullDllName = NotificationData->Loaded.FullDllName->pBuffer;
		std::string DllName = Utils::Get( ).ConvertLPCWSTRToString( FullDllName );
		{
			std::lock_guard<std::mutex> lock( Monitor->AccessGuard );
			Monitor->PendingLoadedDlls.emplace_back( DllName );
		}
	}
}

void Detections::CheckLoadedDlls( ) {

	{
		std::lock_guard<std::mutex> lock( this->AccessGuard );
		while ( !PendingLoadedDlls.empty( ) )
		{
			LoadedDlls.push_back( PendingLoadedDlls.back( ) );
			PendingLoadedDlls.pop_back( );
		}
	}

	for ( int i = 0; i < LoadedDlls.size( ); i++ ) {
		std::string Dll = LoadedDlls.at( i );
		if ( !Authentication::Get( ).HasSignature( Dll ) )
		{
			LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "Unverified dll loaded: " ) + Dll , RED );
			AddDetection( UNVERIFIED_MODULE_LOADED , DetectionStruct( Dll , DETECTED ) );
		}
		std::this_thread::sleep_for( std::chrono::milliseconds( 1 ) );
	}

	LoadedDlls.clear( );
}



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
		//std::cout << "Erro: Não foi possível encontrar o módulo: " << moduleName << std::endl;
		return false;
	}

	// Obter o endereço da função
	FARPROC funcAddress = GetProcAddress( hModule , functionName.c_str( ) );
	if ( !funcAddress ) {
		// std::cout << "Erro: Não foi possível encontrar a função: " << functionName << std::endl;
		return false;
	}

	// Salvar os primeiros X bytes da função
	BYTE * start = reinterpret_cast< BYTE * >( funcAddress );

	std::ofstream outFile( outputFileName );
	if ( !outFile.is_open( ) ) {
		//std::cout << "Erro: Não foi possível abrir o arquivo: " << outputFileName << std::endl;
		return false;
	}

	outFile << xorstr_( "unsigned char functionBytes[] = {" );
	for ( size_t i = 0; i < byteCount; ++i ) {
		outFile << xorstr_( "0x" ) << std::hex << static_cast< int >( start[ i ] );
		if ( i < byteCount - 1 ) outFile << ", "; // Adiciona vírgula entre os bytes
	}
	outFile << xorstr_( "};" );

	outFile.close( );
	//std::cout << "Os primeiros " << byteCount << " bytes da função foram salvos em: " << outputFileName << std::endl;
	return true;
}


bool Detections::DoesFunctionAppearHooked( std::string moduleName , std::string functionName , const unsigned char * expectedBytes , bool restore ) {
	if ( moduleName.empty( ) || functionName.empty( ) )
		return false;

	if ( !expectedBytes || expectedBytes == nullptr ) {
		SaveFirstFunctionBytes( moduleName , functionName , functionName + xorstr_( ".txt" ) , sizeof( expectedBytes ) );
		return false;
	}

	HMODULE hMod = GetModuleHandleA( moduleName.c_str( ) );
	if ( hMod == NULL ) {
		LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "Couldn't fetch module " ) + moduleName , RED );
		return false;
	}

	UINT64 AddressFunction = ( UINT64 ) GetProcAddress( hMod , functionName.c_str( ) );
	if ( AddressFunction == NULL ) {
		LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "Couldn't fetch address of function " ) + functionName , RED );
		return false;
	}

	bool FOUND_HOOK = false;

	unsigned char buffer[ sizeof( expectedBytes ) ]; // Substituí sizeof(expectedBytes) por um tamanho fixo
	SIZE_T bytesRead;
	SIZE_T bytesWritten;

	// Leia os primeiros bytes da função
	if ( ReadProcessMemory( GetCurrentProcess( ) , ( void * ) AddressFunction , buffer , sizeof( expectedBytes ) , &bytesRead ) ) {
		// Verifique se os bytes diferem dos esperados
		if ( memcmp( buffer , expectedBytes , sizeof( expectedBytes ) ) != 0 ) {
			FOUND_HOOK = true;
			if ( restore ) {
				LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "Function " ) + functionName + xorstr_( " appears to be hooked! Restoring original bytes..." ) , YELLOW );

				// Restaure os bytes originais
				if ( WriteProcessMemory( GetCurrentProcess( ) , ( void * ) AddressFunction , expectedBytes , sizeof( expectedBytes ) , &bytesWritten ) ) {
					LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "Successfully restored original bytes for function " ) + functionName , GREEN );
				}
				else {
					LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "Failed to restore original bytes for function " ) + functionName , RED );
				}
			}
		}
	}
	else {
		LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "Failed to read function memory for " ) + functionName , RED );
	}

	return FOUND_HOOK;
}


enum OsType {
	Windows10 ,
	Windows11 ,
	Neither ,
	OUTDATEDAASYSTEM,
	CANTCATCH
};

typedef NTSTATUS( WINAPI * RtlGetVersionPtr )( PRTL_OSVERSIONINFOW );
OsType GetWindowsVersion( ) {
	RTL_OSVERSIONINFOW osInfo = { sizeof( RTL_OSVERSIONINFOW ) };
	HMODULE hNtDll = GetModuleHandleW( L"ntdll.dll" );
	if ( hNtDll ) {
		RtlGetVersionPtr pRtlGetVersion = ( RtlGetVersionPtr ) GetProcAddress( hNtDll , "RtlGetVersion" );
		if ( pRtlGetVersion && NT_SUCCESS( pRtlGetVersion( &osInfo ) ) ) {
			if ( osInfo.dwMajorVersion == 10 ) {
				if ( osInfo.dwBuildNumber >= 22000 ) {
					return OsType::Windows11;
				}
				else {
					return OsType::Windows10;
				}
			}
			else {
				return OsType::Neither;
			}
		}
		else {
			return OsType::OUTDATEDAASYSTEM;
		}
	}
	else {
		return OsType::CANTCATCH;
	}
}



bool Detections::UsingReshade( ) {
	//Reshade appears to change these functions byte

	{
		unsigned char SENDfunctionBytes[ ] = {
			0xe9, 0xae, 0xe7, 0xdb, 0xfe, 0x48, 0x89, 0x6c, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x57
		};

		if ( this->DoesFunctionAppearHooked( xorstr_( "ws2_32.dll" ) , xorstr_( "send" ) , SENDfunctionBytes , false ) ) {
			return false;
		}
	}

	{
		unsigned char RECVfunctionBytes[ ] = {
			0xe9, 0xbe, 0xed, 0xda, 0xfe, 0x48, 0x89, 0x74, 0x24, 0x10, 0x44, 0x89, 0x4c, 0x24, 0x20, 0x55
		};

		if ( this->DoesFunctionAppearHooked( xorstr_( "ws2_32.dll" ) , xorstr_( "recv" ) , RECVfunctionBytes , false ) ) {
			return false;
		}
	}

	return true;
}


void Detections::CheckFunctions( ) {

	if ( !UsingReshade( ) ) {
		OsType OSVersion = GetWindowsVersion( );
		std::vector<unsigned char> SENDfunctionBytes;
		std::vector<unsigned char> RECVfunctionBytes;


		switch ( OSVersion ) {
		case Windows10:

			SENDfunctionBytes = {
			0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18
			};

			RECVfunctionBytes = {
		0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10, 0x44, 0x89, 0x4C, 0x24, 0x20
			};

			break;

		case Windows11:

			RECVfunctionBytes = {
				0x48, 0x89, 0x5c, 0x24, 0x8, 0x48, 0x89, 0x6c, 0x24, 0x10, 0x44, 0x89, 0x4c, 0x24, 0x20, 0x56
			};

			SENDfunctionBytes = {
			0x48, 0x89, 0x5c, 0x24, 0x8, 0x48, 0x89, 0x6c, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x57
			};

			break;

		default:
			LogSystem::Get( ).Log( xorstr_( "Incompatible OS Version!" ) );
			goto out;
		}

		if ( this->DoesFunctionAppearHooked( xorstr_( "ws2_32.dll" ) , xorstr_( "send" ) , SENDfunctionBytes.data( ) , true ) ) {
			AddDetection( FUNCTION_HOOKED , DetectionStruct( xorstr_( "ws2_32.dll:send() hooked" ) , DETECTED ) );
			LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "ws2_32.dll:send() hooked" ) , RED );
		}

		if ( this->DoesFunctionAppearHooked( xorstr_( "ws2_32.dll" ) , xorstr_( "recv" ) , RECVfunctionBytes.data( ) , true ) ) {
			AddDetection( FUNCTION_HOOKED , DetectionStruct( xorstr_( "ws2_32.dll:recv() hooked" ) , DETECTED ) );
			LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "ws2_32.dll:recv() hooked" ) , RED );
		}

	}
	
out:
	return;

}


// Verifica handles suspeitos
void Detections::CheckHandles( ) {
	std::vector<_SYSTEM_HANDLE> handles = Mem::Handle::Get( ).DetectOpenHandlesToProcess( );

	for ( auto & handle : handles )
	{
		if ( DoesProcessHaveOpenHandleTous( handle.ProcessId , handles ) )
		{
			std::string ProcessPath = Mem::Get( ).GetProcessExecutablePath( handle.ProcessId );



			/*
			* System processes
			Process C:\Windows\System32\svchost.exe has open handle to us!
			Process C:\Windows\System32\conhost.exe has open handle to us!
			  Process D:\Program Files (x86)\Steam\steam.exe
			  C:\\Windows\\System32\\audiodg.exe
			  C:\\Windows\\System32\\lsass.exe
			*/
			if ( !strcmp( ProcessPath.c_str( ) , xorstr_( "C:\\Program Files\\AMD\\CNext\\CNext\\RadeonSoftware.exe" ) ) ) {
				HANDLE ProcessHandle = Mem::Get( ).GetProcessHandle( handle.ProcessId );
				if ( ProcessHandle != NULL ) {
					TerminateProcess( ProcessHandle , 1 );
					CloseHandle( ProcessHandle );
				}
				continue;
			}

			if ( !strcmp( ProcessPath.c_str( ) , xorstr_( "C:\\Windows\\System32\\audiodg.exe" ) ) ) {
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
					if ( Mem::Handle::Get( ).CheckDangerousPermissions( duplicatedHandle , nullptr ) ) {
						LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "Process " ) + Mem::Get( ).GetProcessExecutablePath( handle.ProcessId ) + xorstr_( " has open handle to us!" ) , RED );

						if ( InjectProcess( handle.ProcessId ) ) {
							LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "Dumpped nigga :)" ) , GREEN );
						}

						/*if ( !Authentication::Get( ).HasSignature( ProcessPath ) ) {
							LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "Process " ) + Mem::Get( ).GetProcessExecutablePath( handle.ProcessId ) + xorstr_( " has open handle to us!" ) , RED );
						}*/
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

		client newclient;

		while ( !newclient.SendMessageToServer( FinalInfo , Ban ? BAN : WARN ) ) {
			Sleep( 10000 );
		}
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
		CheckLoadedDlls( );
		DigestDetections( );
		std::this_thread::sleep_for( std::chrono::seconds( 10 ) );
	}
}
