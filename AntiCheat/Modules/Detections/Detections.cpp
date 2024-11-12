#include "Detections.h"
#include <iostream>
#include <thread>
#include <Windows.h>
#include <unordered_map>
#include <memory.h>

#include "../../Systems/AntiTamper/Authentication.h"
#include "../../Systems/Memory/memory.h"
#include "../../Systems/Utils/xorstr.h"
#include "../../Systems/Monitoring/Monitoring.h"
#include "../../Systems/LogSystem/Log.h"
#include "../../Globals/Globals.h"
#include "../../Systems/Utils/utils.h"
#include "../../Systems/Injection/Injection.h"
#include "../../Systems/Services/Services.h"	
#include "../../Client/client.h"

#include <TlHelp32.h>



Detections::Detections( ) {
	HMODULE hNtdll = GetModuleHandleA( xorstr_( "ntdll.dll" ) );
	if ( hNtdll != 0 ) //register DLL notifications callback 
	{
		_LdrRegisterDllNotification pLdrRegisterDllNotification = ( _LdrRegisterDllNotification ) GetProcAddress( hNtdll , "LdrRegisterDllNotification" );
		PVOID cookie;
		NTSTATUS status = pLdrRegisterDllNotification( 0 , ( PLDR_DLL_NOTIFICATION_FUNCTION ) OnDllNotification , this , &cookie );
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

bool Detections::isRunning( ) const {
	if ( this->ThreadObject->IsThreadSuspended( this->ThreadObject->GetHandle( ) ) ) {
		client::Get( ).SendPunishToServer( xorstr_( "Detections thread was found suspended, abormal execution" ) , true );
		LogSystem::Get( ).Log( xorstr_( "Failed to run thread" ) );
	}

	if ( !this->ThreadObject->IsThreadRunning( this->ThreadObject->GetHandle( ) ) && !this->ThreadObject->IsShutdownSignalled( ) ) {
		client::Get( ).SendPunishToServer( xorstr_( "Detections thread was found terminated, abormal execution" ) , true );
		LogSystem::Get( ).Log( xorstr_( "Failed to run thread" ) );
	}

	return true;
}

void Detections::CheckLoadedDrivers( ) {

	std::vector<std::string> LoadedDrivers;
	if ( Services::Get( ).GetLoadedDrivers( &LoadedDrivers ) ) {

		std::string toReplace = xorstr_( "\\SystemRoot\\" );
		std::string replacement = xorstr_( "C:\\WINDOWS\\" );

		for ( auto Driver : LoadedDrivers ) {

			if ( Utils::Get( ).CheckStrings( Driver , xorstr_( "dump_diskdump.sys" ) )
				|| Utils::Get( ).CheckStrings( Driver , xorstr_( "dump_dumpfve.sys" ) )
				|| Utils::Get( ).CheckStrings( Driver , xorstr_( "dump_storahci.sys" ) ) ) {
				LogSystem::Get( ).Log( xorstr_( "[203] Windows dump files found" ) );
			}

			size_t pos = Driver.find( toReplace );
			while ( pos != std::string::npos ) {
				Driver.replace( pos , toReplace.length( ) , replacement );
				pos = Driver.find( toReplace , pos + replacement.length( ) );
			}

			if ( !Authentication::Get( ).HasSignature( Driver ) )
			{
				Utils::Get( ).WarnMessage( _DETECTION , xorstr_( "Unverified Driver loaded: " ) + Driver , RED );
				AddDetection( UNVERIFIED_DRIVER_RUNNING , DetectionStruct( Driver , DETECTED ) );
			}
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
			Utils::Get( ).WarnMessage( _DETECTION , xorstr_( "Unverified dll loaded: " ) + Dll , RED );
			AddDetection( UNVERIFIED_MODULE_LOADED , DetectionStruct( Dll , DETECTED ) );
		}
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
	}

	_result += xorstr_( "`" ) + _detection.Log + xorstr_( "`\n" );

	return _result;
}

void Detections::AddDetection( FLAG_DETECTION flag , DetectionStruct _detection ) {
	this->DetectedFlags.emplace_back( std::make_pair( flag , _detection ) );
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

		FinalInfo += xorstr_( "> Cheater detected\n\n" );

		bool Ban = false;

		for ( auto Detection : DetectedFlags ) {
			FinalInfo += this->GenerateDetectionStatus( Detection.first , Detection.second );
			if ( Detection.second._Status == DETECTED )
				Ban = true;
		}

		client::Get( ).SendPunishToServer( FinalInfo , Ban );
		LogSystem::Get( ).Log( xorstr_( "AC Flagged unsafe!" ) );
	}

	this->cDetections.clear( );
}

static BOOL __forceinline AppearHooked( UINT64 AddressFunction ) {
	__try
	{
		if ( *( BYTE * ) AddressFunction == 0xE8 || *( BYTE * ) AddressFunction == 0xE9 || *( BYTE * ) AddressFunction == 0xEA || *( BYTE * ) AddressFunction == 0xEB ) //0xEB = short jump, 0xE8 = call X, 0xE9 = long jump, 0xEA = "jmp oper2:oper1"
			return FALSE;
	}
	__except ( EXCEPTION_EXECUTE_HANDLER )
	{
		return FALSE; //couldn't read memory at function
	}
}



bool Detections::DoesFunctionAppearHooked( std::string moduleName , std::string functionName )
{
	if ( moduleName.empty( ) || functionName.empty( ) )
		return false;

	bool FunctionPreambleHooked = false;

	HMODULE hMod = GetModuleHandleA( moduleName.c_str( ) );
	if ( hMod == NULL )
	{
		Utils::Get( ).WarnMessage( _DETECTION , xorstr_( "Couldn't fetch module " ) + moduleName , RED );
		return false;
	}

	UINT64 AddressFunction = ( UINT64 ) GetProcAddress( hMod , functionName.c_str( ) );

	if ( AddressFunction == NULL )
	{
		Utils::Get( ).WarnMessage( _DETECTION , xorstr_( "Couldn't fetch address of function " ) + functionName , RED );
		return FALSE;
	}

	return AppearHooked( AddressFunction );
}

void Detections::ScanWindows( ) {
	Utils::Get( ).WarnMessage( _DETECTION , xorstr_( "starting window scan" ) , GREEN );
	std::unordered_map<DWORD , int> Map;

	// Enumerate all top-level windows
	std::vector<WindowInfo> Windows;
	EnumWindows( Mem::EnumWindowsProc , ( LPARAM ) ( &Windows ) );

	std::unordered_map<HWND , DWORD> DetectedWindows;


	for ( const auto & window : Windows ) {


		// Check for overlay characteristics
		LONG_PTR exStyle = GetWindowLongPtr( window.hwnd , GWL_EXSTYLE );
		if ( ( exStyle & WS_EX_LAYERED ) && ( exStyle & WS_EX_TRANSPARENT ) ) {
			if ( Map[ window.processId ] == true ) {
				continue;
			}
			std::string ProcessName = Mem::Get( ).GetProcessName( window.processId );

			RECT overlayRect;
			if ( GetWindowRect( window.hwnd , &overlayRect ) ) {

				if ( !overlayRect.left && !overlayRect.right && !overlayRect.bottom && !overlayRect.top )
					continue;

				//emplace_item on map
				Map[ window.processId ] = true;
			}
		}

		DWORD windowAffinity = NULL;
		if ( !GetWindowDisplayAffinity( window.hwnd , &windowAffinity ) ) {
			continue;
		}
		if ( windowAffinity != WDA_NONE ) {
			//Utils::Get( ).WarnMessage( _DETECTION , xorstr_( "got window affinity of id " ) + std::to_string( window.processId ) , GREEN );
			DetectedWindows[ window.hwnd ] = window.processId;
		}
	}

	if ( !DetectedWindows.empty( ) ) {
		std::string Log = "";
		for ( const auto & pair : DetectedWindows ) {
			Injector::Get( ).Inject( xorstr_( "windows.dll" ) , pair.second );
			Log += Mem::Get( ).GetProcessExecutablePath( pair.second ) + xorstr_( "\n" );
		}

		AddDetection( HIDE_FROM_CAPTURE_WINDOW , DetectionStruct( Log , DETECTED ) );
	}

	for ( const auto & pair : Map ) {

		HANDLE hProcess = OpenProcess( PROCESS_VM_READ | PROCESS_QUERY_INFORMATION , FALSE , pair.first );
		if ( hProcess == NULL )
			continue;

		std::string ProcessName = Mem::Get( ).GetProcessName( pair.first );
		std::string ProcessPath = Mem::Get( ).GetProcessExecutablePath( pair.first );


		if ( !Authentication::Get( ).HasSignature( ProcessPath ) ) {
			AddDetection( SUSPECT_WINDOW_OPEN , DetectionStruct( ProcessPath , SUSPECT ) );
			Utils::Get( ).WarnMessage( _DETECTION , xorstr_( "process " ) + ProcessName + xorstr_( " has open window!" ) , YELLOW );
		}
		else {


		}

		//Utils::Get( ).WarnMessage( _DETECTION  , xorstr_( "scanning " ) + ProcessName , WHITE );


		CloseHandle( hProcess );
	}
	Utils::Get( ).WarnMessage( _DETECTION , xorstr_( "ending window scan" ) , GREEN );
	this->ScanModules( );
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

	Utils::Get( ).WarnMessage( _DETECTION , xorstr_( "scanning modules" ) , WHITE );
}

void Detections::ScanParentModules( ) {
	std::vector<std::string> MomModules = Mem::Get( ).GetModules( this->MomProcess );

	for ( auto MomModule : MomModules ) {

	}
}

void Detections::CheckFunctions( ) {
	/*if ( this->DoesFunctionAppearHooked( xorstr_( "ws2_32.dll" ) , xorstr_( "send" ) ) ) {
		AddDetection( FUNCTION_HOOKED , DetectionStruct( xorstr_("ws2_32.dll:send() hooked" ) , SUSPECT ) );
	}

	if ( this->DoesFunctionAppearHooked( xorstr_( "ws2_32.dll" ) , xorstr_( "recv" ) ) ) {
		AddDetection( FUNCTION_HOOKED , DetectionStruct( xorstr_( "ws2_32.dll:recv() hooked" ) , SUSPECT ) );
	}*/
}

void Detections::threadFunction( ) {
	Utils::Get( ).WarnMessage( _DETECTION , xorstr_( "thread started sucessfully, id: " ) + std::to_string( this->ThreadObject->GetId( ) ) , GREEN );
	bool Running = true;

	while ( Running ) {

		if ( this->ThreadObject->IsShutdownSignalled( ) ) {
			Utils::Get( ).WarnMessage( _DETECTION , xorstr_( "shutdown thread signalled" ) , YELLOW );
			return;
		}

		if ( Services::Get( ).IsTestsigningEnabled( ) || Services::Get( ).IsDebugModeEnabled( ) ) {
			LogSystem::Get( ).Log( xorstr_( "Test signing or debug mode is enabled" ) );
		}

		Utils::Get( ).WarnMessage( _DETECTION , xorstr_( "checking functions!" ) , GRAY );
		this->CheckFunctions( );
		Utils::Get( ).WarnMessage( _DETECTION , xorstr_( "scanning loaded drivers!" ) , GRAY );
		this->CheckLoadedDrivers( );

		Utils::Get( ).WarnMessage( _DETECTION , xorstr_( "scanning loaded dlls!" ) , GRAY );
		this->CheckLoadedDlls( );

		Utils::Get( ).WarnMessage( _DETECTION , xorstr_( "scanning open windows!" ) , GRAY );
		this->ScanWindows( );

		Utils::Get( ).WarnMessage( _DETECTION , xorstr_( "scanning parent modules!" ) , GRAY );
		this->ScanParentModules( );

		Utils::Get( ).WarnMessage( _DETECTION , xorstr_( "digesting detecions!" ) , GRAY );
		this->DigestDetections( );

		Utils::Get( ).WarnMessage( _DETECTION , xorstr_( "detection thread" ) , GRAY );

		std::this_thread::sleep_for( std::chrono::seconds( this->getThreadSleepTime( ) ) );
	}
}