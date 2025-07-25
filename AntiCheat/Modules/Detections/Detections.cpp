#include "Detections.h"
#include <iostream>
#include <thread>
#include <Windows.h>
#include <unordered_map>
#include <memory.h>
#include <fstream>

#include "../ThreadGuard/ThreadGuard.h"

#include "../../Systems/AntiTamper/Authentication.h"
#include "../../Systems/Memory/memory.h"
#include "../../Systems/Utils/xorstr.h"
#include "../../Systems/Monitoring/Monitoring.h"
#include "../../Systems/LogSystem/Log.h"
#include "../../Systems/LogSystem/File/File.h"
#include "../../Globals/Globals.h"
#include "../../Systems/Utils/utils.h"
#include "../../Systems/Injection/Injection.h"
#include "../../Systems/Services/Services.h"	
#include "../../Client/client.h"


#include <TlHelp32.h>
#include <set>
#include <winternl.h>

#include <nlohmann/json.hpp>

using nlohmann::json;


void Detections::InitializeThreads( ) {
	for ( ThreadInfo Thread : Mem::Thread::Get( ).EnumerateThreads( GetCurrentProcessId( ) ) ) {
		AllowedThreads.emplace_back( Thread.threadID );
	
	}

	LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "Allowed " ) + std::to_string(AllowedThreads.size() ) + xorstr_(" threads!" ) , GREEN );
}

Detections::Detections( ) 
	: ThreadHolder( THREADS::DETECTIONS )
{
	HMODULE hNtdll = GetModuleHandleA( xorstr_( "ntdll.dll" ) );
	if ( hNtdll != 0 ) //register DLL notifications callback 
	{
		LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "DLL Notification callback loaded" ), GREEN );

		_LdrRegisterDllNotification pLdrRegisterDllNotification = ( _LdrRegisterDllNotification ) GetProcAddress( hNtdll , xorstr_( "LdrRegisterDllNotification" ) );
		PVOID cookie;
		NTSTATUS status = pLdrRegisterDllNotification( 0 , ( PLDR_DLL_NOTIFICATION_FUNCTION ) OnDllNotification , this , &cookie );
	}
	else {
		LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "DLL Notification callback failed" ) , RED );
	}
}


void Detections::SetupPid( DWORD _MomProcess , DWORD _ProtectProcess ) {
	this->MomProcess = _MomProcess;
	this->ProtectProcess = _ProtectProcess;
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

Detections::~Detections( ) {
	stop( );
}




bool DumpedDrivers = false;

void Detections::CheckLoadedDrivers( ) {

	std::vector<std::string> LoadedDrivers;
	if ( Services::Get( ).GetLoadedDrivers( &LoadedDrivers ) ) {

		std::string toReplace = xorstr_( "\\SystemRoot\\" );
		std::string replacement = xorstr_( "C:\\WINDOWS\\" );

		if ( !DumpedDrivers ) {
			File DumpDrivers( "DriversDump.txt" );
			json Js;
			Js[ "drivers" ] = LoadedDrivers;
			DumpDrivers.Write( Js.dump( ) );
			DumpedDrivers = true;
		}

		for ( auto Driver : LoadedDrivers ) {

			if ( Utils::Get( ).CheckStrings( Driver , xorstr_( "dump_diskdump.sys" ) )
				|| Utils::Get( ).CheckStrings( Driver , xorstr_( "dump_dumpfve.sys" ) )
				|| Utils::Get( ).CheckStrings( Driver , xorstr_( "dump_storahci.sys" ) ) ) {
				LogSystem::Get( ).Error( xorstr_( "[203] Windows dump files found" ) );
				continue;
			}

			if ( Utils::Get( ).CheckStrings( Driver , xorstr_( "kprocesshacker.sys" ) ) ) {
				LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "ProcessHacker Driver Loaded!" ) , YELLOW );
				AddDetection( UNVERIFIED_DRIVER_RUNNING , DetectionStruct( Driver , SUSPECT ) );
			}

			size_t pos = Driver.find( toReplace );
			while ( pos != std::string::npos ) {
				Driver.replace( pos , toReplace.length( ) , replacement );
				pos = Driver.find( toReplace , pos + replacement.length( ) );
			}

			if ( !Authentication::Get( ).HasSignature( Driver ) )
			{
				LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "Unverified Driver loaded: " ) + Driver , RED );
				AddDetection( UNVERIFIED_DRIVER_RUNNING , DetectionStruct( Driver , DETECTED ) );
			}
			std::this_thread::sleep_for( std::chrono::milliseconds( 5 ) );
		}
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

// M�todo de inje��o
bool Detections::InjectProcess( DWORD processId ) {
	char exePath[ MAX_PATH ];
	GetModuleFileNameA( NULL , exePath , MAX_PATH );
	std::string exePathStr( exePath );

	auto find = this->InjectedProcesses.find( processId );
	if ( find != this->InjectedProcesses.end( ) ) {
		return false;
	}

	if ( Injector::Get( ).InjectBytes( _globals.encryptedDumper , processId ) ) {
		this->InjectedProcesses[ processId ] = true;
		LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "Dumped " ) + Mem::Get( ).GetProcessName( processId ), GREEN);
		return true;
	}

	return false;
}

void Detections::CheckOpenHandles( ) {
	std::vector<_SYSTEM_HANDLE> handles = Mem::Handle::Get( ).DetectOpenHandlesToProcess( );

	for ( auto & handle : handles )
	{
		if ( handle.ProcessId == _globals.ProtectProcess )
			continue;

		if ( DoesProcessHaveOpenHandleTous( handle.ProcessId , handles ) )
		{
			/*
			* System processes
			Process C:\Windows\System32\svchost.exe has open handle to us!
			Process C:\Windows\System32\conhost.exe has open handle to us!
			C:\Windows\System32\lsass.exe
			*/



			std::string ProcessPath = Mem::Get( ).GetProcessExecutablePath( handle.ProcessId );


			if ( !strcmp( ProcessPath.c_str( ) , xorstr_( "C:\\Program Files\\AMD\\CNext\\CNext\\RadeonSoftware.exe" ) ) ) {
				HANDLE ProcessHandle = Mem::Get( ).GetProcessHandle( handle.ProcessId );
				if ( ProcessHandle != NULL ) {
					TerminateProcess( ProcessHandle , 1 );
					CloseHandle( ProcessHandle );
				}
				continue;
			}

			if ( !strcmp( ProcessPath.c_str( ) , xorstr_( "C:\\Windows\\System32\\audiodg.exe" ) ) ) 
				continue;
			
			if ( !strcmp( ProcessPath.c_str( ) , xorstr_( "C:\\Windows\\System32\\lsass.exe" ) ) ) 
				continue;
			
			if ( !strcmp( ProcessPath.c_str( ) , xorstr_( "C:\\Windows\\System32\\conhost.exe" ) ) )
				continue;

			if ( !strcmp( ProcessPath.c_str( ) , xorstr_( "C:\\Windows\\System32\\svchost.exe" ) ) )
				continue;

			if ( !strcmp( ProcessPath.c_str( ) , xorstr_( "C:\\Windows\\System32\\lsass.exe" ) ) )
				continue;

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

						AddDetection( OPENHANDLE_TO_US , DetectionStruct( ProcessPath , SUSPECT ) );

						if ( !InjectProcess( handle.ProcessId ) ) {
							LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "Can't dump process" ) , RED );
						}

					}
					else
						LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "Process " ) + Mem::Get( ).GetProcessExecutablePath( handle.ProcessId ) + xorstr_( " has open handle to us!" ) , YELLOW );


					if ( duplicatedHandle != INVALID_HANDLE_VALUE )
						CloseHandle( duplicatedHandle );
				}

				CloseHandle( processHandle );
			}

			LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "Process " ) + Mem::Get( ).GetProcessExecutablePath( handle.ProcessId ) + xorstr_( " has open handle to us!" ) , RED );
			//Logger::logfw( "UltimateAnticheat.log" , Detection , L"Process %s has open process handle to our process." , procName.c_str( ) );
			//foundHandle = TRUE;
			//continue;
		}
	}
}

void Detections::CheckLoadedDlls( ) {

	{
		std::vector<std::string> NameCopy;
		{
			std::lock_guard<std::mutex> lock( this->AccessGuard );
			NameCopy = PendingLoadedDlls;
			PendingLoadedDlls.clear( );
		}

		while ( !NameCopy.empty( ) )
		{
			LoadedDlls.push_back( NameCopy.back( ) );
			NameCopy.pop_back( );
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
	case INVALID_THREAD_CREATION:
		_result += xorstr_( "** Invalid Thread creation attempted **\n" );
		break;
	case IAT_HOOKED:
		_result += xorstr_( "** IAT Hooked **\n" );
		break;
	}

	_result += xorstr_( "`" ) + _detection.Log + xorstr_( "`\n" );

	return _result;
}

void Detections::AddDetection( FLAG_DETECTION flag , DetectionStruct _detection ) {
	this->DetectedFlags.emplace_back( std::make_pair( flag , _detection ) );
}

void Detections::DigestDetections( ) {


	static std::vector<std::pair<FLAG_DETECTION , DetectionStruct>> OldDetectedFlags;
	{
		std::lock_guard<std::mutex> lock( this->ExternalDetectionsAcessGuard );
		if ( !ExternalDetectedFlags.empty( ) ) {
			for ( auto __Detection : ExternalDetectedFlags ) {
				DetectedFlags.emplace_back( __Detection );
			}
			ExternalDetectedFlags.clear( );
		}
	}

	if ( DetectedFlags.empty( ) ) {
		return;
	}

	/*
	* DIGEST DETECTION
	*/
	std::string FinalInfo = "";

	FinalInfo += xorstr_( "> AC FLAG detected\n\n" );

	bool Ban = false;
	int Elapsed = 0;

	std::vector<std::pair<FLAG_DETECTION , DetectionStruct>> OldCopy = OldDetectedFlags;

	for ( auto Detection : DetectedFlags ) {
		if ( Detection.second._Status != DETECTED )
		{
			bool Skip = false;

			for ( auto OldDetection : OldCopy ) {
				if ( OldDetection.first == Detection.first
					&& OldDetection.second._Status == Detection.second._Status
					&& !strcmp( OldDetection.second.Log.c_str( ) , Detection.second.Log.c_str( ) ) ) {
					Skip = true;
					break;
				}
			}

			if ( Skip )
				continue;

			OldDetectedFlags.emplace_back( Detection );
		}

		FinalInfo += this->GenerateDetectionStatus( Detection.first , Detection.second );
		if ( Detection.second._Status == DETECTED )
			Ban = true;
		Elapsed++;
	}

	if ( !Elapsed )
		return;


	if ( _client.SendPunishToServer( FinalInfo , Ban ? BAN : WARN ) ) {
		LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "Sent Punish to server sucessfully!" ) , GREEN );
		this->DetectedFlags.clear( );

		if ( Ban )
			LogSystem::Get( ).Error( xorstr_( "AC Flagged unsafe!" ) );
	}
	else {
		// Don`t erase the detection vector, we will try again later!
		LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "Failed to send punish to server" ) , RED );
	}
}


bool SaveFirstFunctionBytes( const std::string & moduleName , const std::string & functionName , const std::string & outputFileName , size_t byteCount ) {
	HMODULE hModule = GetModuleHandleA( moduleName.c_str( ) );
	if ( !hModule ) {
		std::cerr << "Erro: N�o foi poss�vel encontrar o m�dulo: " << moduleName << std::endl;
		return false;
	}

	FARPROC funcAddress = GetProcAddress( hModule , functionName.c_str( ) );
	if ( !funcAddress ) {
		std::cerr << "Erro: N�o foi poss�vel encontrar a fun��o: " << functionName << std::endl;
		return false;
	}

	BYTE * start = reinterpret_cast< BYTE * >( funcAddress );

	std::ofstream outFile( outputFileName );
	if ( !outFile.is_open( ) ) {
		std::cerr << "Erro: N�o foi poss�vel abrir o arquivo: " << outputFileName << std::endl;
		return false;
	}

	outFile << "unsigned char functionBytes[] = {";
	for ( size_t i = 0; i < byteCount; ++i ) {
		outFile << "0x" << std::hex << static_cast< int >( start[ i ] );
		if ( i < byteCount - 1 ) outFile << ", "; // Adiciona v�rgula entre os bytes
	}
	outFile << "};" << std::endl;

	outFile.close( );
	return true;
}

void Detections::AddExternalDetection( FLAG_DETECTION  flag , DetectionStruct  _detection ) {
	std::lock_guard<std::mutex> lock( this->ExternalDetectionsAcessGuard );
	this->ExternalDetectedFlags.emplace_back( std::make_pair( flag , _detection ) );
	LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "Received External Detection!\n" ) + _detection.Log , YELLOW );
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

	unsigned char buffer[ sizeof( expectedBytes ) ]; // Substitu� sizeof(expectedBytes) por um tamanho fixo
	SIZE_T bytesRead;
	SIZE_T bytesWritten;

	// Leia os primeiros bytes da fun��o
	if ( ReadProcessMemory( GetCurrentProcess( ) , ( void * ) AddressFunction , buffer , sizeof( expectedBytes ) , &bytesRead ) ) {
		// Verifique se os bytes diferem dos esperados
		if ( memcmp( buffer , expectedBytes , sizeof( expectedBytes ) ) != 0 ) {
			FOUND_HOOK = true;
			LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "Function " ) + functionName + xorstr_( " appears to be hooked! Restoring original bytes..." ) , YELLOW );

			if ( restore ) {
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

void Detections::ScanWindows( ) {
	LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "starting window scan" ) , GREEN );

	std::unordered_map<DWORD , bool> processedProcesses;

	// Enumerate all top-level windows
	std::vector<WindowInfo> windows;
	EnumWindows( Mem::EnumWindowsProc , reinterpret_cast< LPARAM >( &windows ) );

	for ( const auto & window : windows ) {
		// Check for overlay characteristics
		LONG_PTR exStyle = GetWindowLongPtr( window.hwnd , GWL_EXSTYLE );
		if ( ( exStyle & WS_EX_LAYERED ) && ( exStyle & WS_EX_TRANSPARENT ) && !processedProcesses[ window.processId ] ) {

			RECT overlayRect;

			if ( !GetWindowRect( window.hwnd , &overlayRect ) &&
				( overlayRect.left || overlayRect.right || overlayRect.bottom || overlayRect.top ) )
				continue;
			// Mark process as processed 

			DWORD windowAffinity;
			if ( GetWindowDisplayAffinity( window.hwnd , &windowAffinity ) && windowAffinity != WDA_NONE ) {
				std::string logMessage = Mem::Get( ).GetProcessExecutablePath( window.processId ) + xorstr_( "\n" );
				InjectProcess( window.processId );
				AddDetection( HIDE_FROM_CAPTURE_WINDOW , DetectionStruct( logMessage , DETECTED ) );
			}

			processedProcesses[ window.processId ] = true;
		}

		std::this_thread::sleep_for( std::chrono::milliseconds( 1 ) );
	}

	for ( const auto & [processId , _] : processedProcesses ) {

		if ( processId == 4 || processId == 0 || processId == _globals.ProtectProcess )
			continue;

		HANDLE hProcess = OpenProcess( PROCESS_VM_READ | PROCESS_QUERY_INFORMATION , FALSE , processId );
		if ( hProcess ) {
			std::string processPath = Mem::Get( ).GetProcessExecutablePath( processId );


			if ( !Authentication::Get( ).HasSignature( processPath ) ) {
				AddDetection( SUSPECT_WINDOW_OPEN , DetectionStruct( processPath , SUSPECT ) );
				LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "process " ) + Mem::Get( ).GetProcessName( processId ) + xorstr_( " has open window!" ) , YELLOW );
			}
			else {
				std::string processName = Mem::Get( ).GetProcessName( processId );

				//signed process, but does it has a bad module?
				std::vector<ModuleInfo> LoadedModules = Mem::Module::Get( ).EnumerateModules( processId );

				for ( ModuleInfo & Module : LoadedModules ) {
					if ( !Authentication::Get( ).HasSignature( Module.modulePath ) ) {
						AddDetection( SUSPECT_WINDOW_OPEN , DetectionStruct( processPath + xorstr_( ": " ) + Module.modulePath , SUSPECT ) );
						LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "process " ) + Mem::Get( ).GetProcessName( processId ) + xorstr_( ":(" ) + Module.modulePath + xorstr_( ") has open window!" ) , YELLOW );
						break;
					}
				}

				{
					static const std::set<std::string> systemProcesses = {
						xorstr_( "taskmgr.exe" ),
						xorstr_( "msconfig.exe" ),
						xorstr_( "control.exe" ),
						xorstr_( "winlogon.exe" ),
						xorstr_( "services.exe" ),
						xorstr_( "regedit.exe" ),
						xorstr_( "cmd.exe" ),
						xorstr_( "notepad.exe" ),
						xorstr_( "rundll32.exe" ),
						xorstr_( "mspmsnsv.exe" ),
						xorstr_( "shell32.dll" )
					};

					// Comparar o nome do processo criptografado com a lista
					if ( std::find( systemProcesses.begin( ) , systemProcesses.end( ) , processName.c_str( ) ) != systemProcesses.end( ) ) {
						AddDetection( SUSPECT_WINDOW_OPEN , DetectionStruct( processPath , DETECTED ) );
						LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "process " ) + Mem::Get( ).GetProcessName( processId ) + xorstr_( " has open window!" ) , RED );
					}
				}
			}
			CloseHandle( hProcess );
		}
		std::this_thread::sleep_for( std::chrono::milliseconds( 1 ) );
	}

	LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "ending window scan" ) , GREEN );
}

void Detections::ScanModules( ) {

	/*
	IDEA:
	Create a DB with the current modules
	With more people using the AC, the more data about processes you will have

	If we find a completely differente module, just get the module file
	send it
	and pop a warning
	*/
	std::vector<ModuleInfo> LoadedModules = Mem::Module::Get( ).EnumerateModules( _globals.SelfID );

	for ( ModuleInfo & Module : LoadedModules ) {

		bool iatHooked = IsIATHooked( Module.moduleName );

		if ( iatHooked ) {
			AddDetection( IAT_HOOKED , DetectionStruct( Module.moduleName + xorstr_( ": IAT HOOKED" ) , SUSPECT ) );
		}

		std::string StringStatus = iatHooked ? xorstr_( "true" ) : xorstr_( "false" );

		LogSystem::Get( ).ConsoleLog( _DETECTION , Module.moduleName + xorstr_( " IAT Hooked: " ) + StringStatus , iatHooked? RED :GRAY );

	}
}

void Detections::ScanParentModules( ) {
	/*std::vector<ModuleInfo> MomModules = Mem::Module::Get( ).EnumerateModules( this->MomProcess );

	for ( auto MomModule : MomModules ) {

	}*/
}

bool Detections::IsEATHooked( std::string & moduleName ) {
	HMODULE module = GetModuleHandleA( moduleName.c_str( ) );
	if ( !module ) {
		LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "Failed to get module handle for: " ) + moduleName , RED );
		return false;
	}

	auto dosHeader = reinterpret_cast< PIMAGE_DOS_HEADER >( module );
	auto ntHeaders = reinterpret_cast< PIMAGE_NT_HEADERS >( reinterpret_cast< uintptr_t >( module ) + dosHeader->e_lfanew );
	auto exportDirectory = reinterpret_cast< PIMAGE_EXPORT_DIRECTORY >(
		reinterpret_cast< uintptr_t >( module ) + ntHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress
		);

	auto functionAddressArray = reinterpret_cast< uintptr_t * >(
		reinterpret_cast< uintptr_t >( module ) + exportDirectory->AddressOfFunctions
		);

	for ( size_t i = 0; i < exportDirectory->NumberOfFunctions; i++ ) {
		uintptr_t functionAddress = reinterpret_cast< uintptr_t >( module ) + functionAddressArray[ i ];
		if ( !VirtualQuery( reinterpret_cast< void * >( functionAddress ) , nullptr , 0 ) ) {
			LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "EAT hook detected for function index: " ) + std::to_string( i ) , RED );
			return true;
		}
	}

	return false;
}



bool Detections::IsIATHooked( std::string & moduleName ) {
	HMODULE module = GetModuleHandleA( moduleName.c_str( ) );
	if ( !module ) {
		LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "Failed to get module handle for: " ) + moduleName , RED );
		return false;
	}

	auto dosHeader = reinterpret_cast< PIMAGE_DOS_HEADER >( module );
	if ( dosHeader->e_magic != IMAGE_DOS_SIGNATURE ) {
		LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "Failed to get dosHeader for: " ) + moduleName , RED );
		return false;
	}

	auto ntHeaders = reinterpret_cast< PIMAGE_NT_HEADERS >( reinterpret_cast< uintptr_t >( module ) + dosHeader->e_lfanew );

	if ( ntHeaders->Signature != IMAGE_NT_SIGNATURE ) {
		LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "Failed to get ntHeaders for: " ) + moduleName , RED );
		return false;
	}

	auto importDir = ntHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];

	if ( !importDir.VirtualAddress || !importDir.Size ) {
		LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "Dont have IAT: " ) + moduleName , RED );
		return false;
	}

	auto importDescriptor = reinterpret_cast< PIMAGE_IMPORT_DESCRIPTOR >(
		reinterpret_cast< uintptr_t >( module ) + ntHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress
		);

	while ( importDescriptor->Name ) {
		const char * dllName = reinterpret_cast< const char * >( reinterpret_cast< uintptr_t >( module ) + importDescriptor->Name );
		HMODULE importedModule = GetModuleHandleA( dllName );

		if ( !importedModule ) {
			importDescriptor++;
			continue;
		}

		auto firstThunk = reinterpret_cast< PIMAGE_THUNK_DATA >(
			reinterpret_cast< uintptr_t >( module ) + importDescriptor->FirstThunk
			);

		while ( firstThunk->u1.Function ) {
			void * realFunction = GetProcAddress( importedModule , reinterpret_cast< const char * >( firstThunk->u1.Function ) );
			if ( realFunction && reinterpret_cast< void * >( firstThunk->u1.Function ) != realFunction ) {
				LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "IAT hook detected for function: " ) + std::string( dllName ) , RED );
				return true;
			}
			firstThunk++;
		}
		importDescriptor++;
	}

	return false;
}

void Detections::CheckFunctions( ) {


	WindowsVersion OSVersion = Services::Get( ).GetWindowsVersion( );
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
		LogSystem::Get( ).Error( xorstr_( "Incompatible OS Version!" ) );
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

out:
	return;

}

void Detections::CheckRunningThreads( ) {

	if ( !RegisteredThreads ) {
		ThreadGuard * Guard = reinterpret_cast< ThreadGuard * >( _globals.GuardMonitorPointer );
		for ( auto ID : Guard->GetRunningThreadsID( ) ) {
			bool Found = false;
			for ( DWORD AllowedThread : AllowedThreads ) {
				if ( ID == AllowedThread ) {
					Found = true;
				}
			}
			if ( !Found ) {
				AllowedThreads.emplace_back( ID );
			}
		}
		AllowedThreads.emplace_back( Guard->ThreadObject->GetId( ) );
		RegisteredThreads = true;
	}

	std::vector<ThreadInfo> CurrentThreadsOnProcess = Mem::Thread::Get( ).EnumerateThreads( GetCurrentProcessId( ) );
	std::vector<ThreadInfo> UnregisteredThread;

	for ( const auto & threadInfo : CurrentThreadsOnProcess ) {
		if ( std::find( AllowedThreads.begin( ) , AllowedThreads.end( ) , threadInfo.threadID ) == AllowedThreads.end( ) ) {
			// Identifica uma thread n�o permitida
			LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "Unauthorized thread detected: " ) + std::to_string( threadInfo.threadID ) , RED );
			//AddDetection( UNAUTHORIZED_THREAD_RUNNING , DetectionStruct( std::to_string( threadInfo.ThreadId ) , DETECTED ) );
		}
	}
}

void Detections::AddThreadToWhitelist( DWORD threadPID ) {
	this->AllowedThreads.emplace_back( threadPID );
}

// define MessageBoxA prototype
using PrototypeMessageBox = int ( WINAPI * )( HWND hWnd , LPCSTR lpText , LPCSTR lpCaption , UINT uType );

// remember memory address of the original MessageBoxA routine
PrototypeMessageBox originalMsgBox = MessageBoxA;

// hooked function with malicious code that eventually calls the original MessageBoxA
int hookedMessageBox( HWND hWnd , LPCSTR lpText , LPCSTR lpCaption , UINT uType )
{
	printf( "gjfdaisobgfidahgfuijdagioufdajhgioufdaiogjfdaisobgfidahgfuijdagioufdajhgioufdaiogjfdaisobgfidahgfuijdagioufdajhgioufdaiogjfdaisobgfidahgfuijdagioufdajhgioufdaiogjfdaisobgfidahgfuijdagioufdajhgioufdaiogjfdaisobgfidahgfuijdagioufdajhgioufdaio\n" );
	// execute the original NessageBoxA
	return originalMsgBox( hWnd , lpText , lpCaption , uType );
}

bool HOOKIAT( )
{
	MessageBoxA( NULL , "Hello Before Hooking" , "Hello Before Hooking" , 0 );
	printf( "[HOOKIAT] Iniciando fun��o HOOKIAT\n" );

	LPVOID imageBase = GetModuleHandleA( NULL );
	if ( !imageBase ) {
		printf( "[HOOKIAT] Falha ao obter o handle do m�dulo %s\n", _globals.ModuleName.c_str() );
		return false;
	}
	printf( "[HOOKIAT] Handle do m�dulo %s obtido com sucesso\n", _globals.ModuleName.c_str( ) );

	PIMAGE_DOS_HEADER dosHeaders = ( PIMAGE_DOS_HEADER ) imageBase;
	if ( dosHeaders->e_magic != IMAGE_DOS_SIGNATURE ) {
		printf( "[HOOKIAT] Assinatura DOS inv�lida\n" );
		return false;
	}

	PIMAGE_NT_HEADERS ntHeaders = ( PIMAGE_NT_HEADERS ) ( ( DWORD_PTR ) imageBase + dosHeaders->e_lfanew );
	if ( ntHeaders->Signature != IMAGE_NT_SIGNATURE ) {
		printf( "[HOOKIAT] Assinatura NT inv�lida\n" );
		return false;
	}

	auto importDir = ntHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];
	if ( !importDir.VirtualAddress || !importDir.Size ) {
		printf( "[HOOKIAT] Diret�rio de importa��o n�o encontrado\n" );
		return false;
	}
	printf( "[HOOKIAT] Diret�rio de importa��o localizado\n" );

	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = ( PIMAGE_IMPORT_DESCRIPTOR ) ( ( DWORD_PTR ) imageBase + importDir.VirtualAddress );
	bool Found = false;

	while ( importDescriptor->Name != NULL )
	{
		if ( Found )
			break;

		LPCSTR libraryName = ( LPCSTR ) ( ( DWORD_PTR ) imageBase + importDescriptor->Name );
		printf( "[HOOKIAT] Verificando biblioteca: %s\n" , libraryName );

		HMODULE library = LoadLibraryA( libraryName );
		if ( !library ) {
			printf( "[HOOKIAT] Falha ao carregar biblioteca: %s\n" , libraryName );
			importDescriptor++;
			continue;
		}

		PIMAGE_THUNK_DATA originalFirstThunk = ( PIMAGE_THUNK_DATA ) ( ( DWORD_PTR ) imageBase + importDescriptor->OriginalFirstThunk );
		PIMAGE_THUNK_DATA firstThunk = ( PIMAGE_THUNK_DATA ) ( ( DWORD_PTR ) imageBase + importDescriptor->FirstThunk );

		while ( originalFirstThunk->u1.AddressOfData != NULL )
		{
			PIMAGE_IMPORT_BY_NAME functionName = ( PIMAGE_IMPORT_BY_NAME ) ( ( DWORD_PTR ) imageBase + originalFirstThunk->u1.AddressOfData );
			printf( "[HOOKIAT] Fun��o importada encontrada: %s\n" , functionName->Name );

			if ( strcmp( functionName->Name , "MessageBoxA" ) == 0 )
			{
				printf( "[HOOKIAT] Encontrada fun��o MessageBoxA! Iniciando hook...\n" );

				DWORD oldProtect = 0;
				if ( VirtualProtect( ( LPVOID ) &firstThunk->u1.Function , sizeof( DWORD_PTR ) , PAGE_READWRITE , &oldProtect ) ) {
					firstThunk->u1.Function = ( DWORD_PTR ) hookedMessageBox;
					VirtualProtect( ( LPVOID ) &firstThunk->u1.Function , sizeof( DWORD_PTR ) , oldProtect , &oldProtect );
					printf( "[HOOKIAT] Hook aplicado com sucesso em MessageBoxA\n" );
					Found = true;
					break;
				}
				else {
					printf( "[HOOKIAT] Falha ao alterar prote��o de mem�ria para hook\n" );
				}
			}

			++originalFirstThunk;
			++firstThunk;
		}

		importDescriptor++;
	}

	MessageBoxA( NULL , "Hello after Hooking" , "Hello after Hooking" , 0 );
	printf( "[HOOKIAT] Fun��o HOOKIAT finalizada\n" );

	return Found;
}
bool doOnce = false;

void Detections::threadFunction( ) {

	


	LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "thread started sucessfully, id: " ) + std::to_string( this->ThreadObject->GetId( ) ) , GREEN );

	if ( !doOnce ) { 
		if ( !HOOKIAT() ) {
			LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "Failed to hook iat" ), RED );
		}
		else {
			LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "Hooked IAT" ) , GREEN );
		}
		doOnce = true;
	} 


	bool Running = true;

	int CurrentDetection = 0;

	while ( Running ) {

		if ( this->ThreadObject->IsShutdownSignalled( ) ) {
			LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "shutting down thread" ) , RED );
			return;
		}

		if ( Services::Get( ).IsTestsigningEnabled( ) || Services::Get( ).IsDebugModeEnabled( ) ) {
			LogSystem::Get( ).Error( xorstr_( "Test signing or debug mode is enabled" ) );
		}


		switch ( CurrentDetection ) {
		case 0:
			LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "checking open handles!" ) , GRAY );
			this->CheckOpenHandles( );
			break;
		case 1:
			LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "checking functions!" ) , GRAY );
			this->CheckFunctions( );
			break;
		case 2:
			LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "scanning loaded drivers!" ) , GRAY );
			this->CheckLoadedDrivers( );
			break;
		case 3:
			LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "scanning loaded dlls!" ) , GRAY );
			this->CheckLoadedDlls( );
			break;
		case 4:
			LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "scanning open windows!" ) , GRAY );
			this->ScanWindows( );
			break;
		case 5:
			LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "scanning running threads!" ) , GRAY );
			this->CheckRunningThreads( );
			break;
		case 6:
			LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "scanning parent modules!" ) , GRAY );
			this->ScanParentModules( );
			break;
		case 7:
			LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "scanning modules!" ) , GRAY );
			this->ScanModules( );
			break;
		case 8:
			LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "digesting detecions!" ) , GRAY );
			this->DigestDetections( );
			break;
		default:
			std::this_thread::sleep_for( std::chrono::seconds( this->getThreadSleepTime( ) ) );
			//SET TO -1, CAUSE ++ = 0, so we wont miss handle verification
			CurrentDetection = -1;
			break;
		}

		LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "ping" ) , GRAY );

		CurrentDetection++;

		std::this_thread::sleep_for( std::chrono::milliseconds( 500 ) );
	}
}