#include "AntiDebugger.h"

//#include <winternl.h>         // Definições de NTSTATUS, estruturas como SYSTEM_KERNEL_DEBUGGER_INFORMATION

#include <iostream>           // Para saída no console (se for utilizada em log)
#include <thread>             // Para manipulação de threads
#include <chrono>             // Para controle de tempo com std::this_thread::sleep_for
#include <string>             // Para manipulação de std::string


#include "../../Client/client.h"
#include "../../Systems/Utils/utils.h"
#include "../../Systems/Utils/xorstr.h"
#include "../../Systems/LogSystem/Log.h"


#include "../../Globals/Globals.h"
#include "../../Process/Process.hpp"

#define MAX_DLLS 256 
#define USER_SHARED_DATA ((KUSER_SHARED_DATA * const)0x7FFE0000)
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef struct _KSYSTEM_TIME
{
	ULONG LowPart;
	LONG High1Time;
	LONG High2Time;
} KSYSTEM_TIME , * PKSYSTEM_TIME;

typedef enum _NT_PRODUCT_TYPE
{
	NtProductWinNt = 1 ,
	NtProductLanManNt = 2 ,
	NtProductServer = 3
} NT_PRODUCT_TYPE;

typedef enum _ALTERNATIVE_ARCHITECTURE_TYPE
{
	StandardDesign = 0 ,
	NEC98x86 = 1 ,
	EndAlternatives = 2
} ALTERNATIVE_ARCHITECTURE_TYPE;

typedef struct _KUSER_SHARED_DATA  //https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-kuser_shared_data
{
	ULONG                         TickCountLowDeprecated;
	ULONG                         TickCountMultiplier;
	KSYSTEM_TIME                  InterruptTime;
	KSYSTEM_TIME                  SystemTime;
	KSYSTEM_TIME                  TimeZoneBias;
	USHORT                        ImageNumberLow;
	USHORT                        ImageNumberHigh;
	WCHAR                         NtSystemRoot[ 260 ];
	ULONG                         MaxStackTraceDepth;
	ULONG                         CryptoExponent;
	ULONG                         TimeZoneId;
	ULONG                         LargePageMinimum;
	ULONG                         AitSamplingValue;
	ULONG                         AppCompatFlag;
	ULONGLONG                     RNGSeedVersion;
	ULONG                         GlobalValidationRunlevel;
	LONG                          TimeZoneBiasStamp;
	ULONG                         NtBuildNumber;
	NT_PRODUCT_TYPE               NtProductType;
	BOOLEAN                       ProductTypeIsValid;
	BOOLEAN                       Reserved0[ 1 ];
	USHORT                        NativeProcessorArchitecture;
	ULONG                         NtMajorVersion;
	ULONG                         NtMinorVersion;
	BOOLEAN                       ProcessorFeatures[ 64 ];
	ULONG                         Reserved1;
	ULONG                         Reserved3;
	ULONG                         TimeSlip;
	ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;
	ULONG                         BootId;
	LARGE_INTEGER                 SystemExpirationDate;
	ULONG                         SuiteMask;
	BOOLEAN                       KdDebuggerEnabled;
	union {
		UCHAR MitigationPolicies;
		struct {
			UCHAR NXSupportPolicy : 2;
			UCHAR SEHValidationPolicy : 2;
			UCHAR CurDirDevicesSkippedForDlls : 2;
			UCHAR Reserved : 2;
		};
	};
	USHORT                        CyclesPerYield;
	ULONG                         ActiveConsoleId;
	ULONG                         DismountCount;
	ULONG                         ComPlusPackage;
	ULONG                         LastSystemRITEventTickCount;
	ULONG                         NumberOfPhysicalPages;
	BOOLEAN                       SafeBootMode;
	union {
		UCHAR VirtualizationFlags;
		struct {
			UCHAR ArchStartedInEl2 : 1;
			UCHAR QcSlIsSupported : 1;
		};
	};
	UCHAR                         Reserved12[ 2 ];
	union
	{
		ULONG SharedDataFlags;
		struct
		{
			ULONG DbgErrorPortPresent : 1;
			ULONG DbgElevationEnabled : 1;
			ULONG DbgVirtEnabled : 1;
			ULONG DbgInstallerDetectEnabled : 1;
			ULONG DbgLkgEnabled : 1;
			ULONG DbgDynProcessorEnabled : 1;
			ULONG DbgConsoleBrokerEnabled : 1;
			ULONG DbgSecureBootEnabled : 1;
			ULONG DbgMultiSessionSku : 1;
			ULONG DbgMultiUsersInSessionSku : 1;
			ULONG DbgStateSeparationEnabled : 1;
			ULONG SpareBits : 21;
		} Dbg;
	} DbgUnion;
	ULONG                         DataFlagsPad[ 1 ];
	ULONGLONG                     TestRetInstruction;
	LONGLONG                      QpcFrequency;
	ULONG                         SystemCall;
	ULONG                         Reserved2;
	ULONGLONG                     FullNumberOfPhysicalPages;
	ULONGLONG                     SystemCallPad[ 1 ];
	union
	{
		KSYSTEM_TIME TickCount;
		ULONG64      TickCountQuad;
		struct
		{
			ULONG ReservedTickCountOverlay[ 3 ];
			ULONG TickCountPad[ 1 ];
		} DUMMYSTRUCTNAME;
	} DUMMYUNIONNAME3;
	ULONG                         Cookie;
	ULONG                         CookiePad[ 1 ];
	LONGLONG                      ConsoleSessionForegroundProcessId;
	ULONGLONG                     TimeUpdateLock;
	ULONGLONG                     BaselineSystemTimeQpc;
	ULONGLONG                     BaselineInterruptTimeQpc;
	ULONGLONG                     QpcSystemTimeIncrement;
	ULONGLONG                     QpcInterruptTimeIncrement;
	UCHAR                         QpcSystemTimeIncrementShift;
	UCHAR                         QpcInterruptTimeIncrementShift;
	USHORT                        UnparkedProcessorCount;
	ULONG                         EnclaveFeatureMask[ 4 ];
	ULONG                         TelemetryCoverageRound;
	USHORT                        UserModeGlobalLogger[ 16 ];
	ULONG                         ImageFileExecutionOptions;
	ULONG                         LangGenerationCount;
	ULONGLONG                     Reserved4;
	ULONGLONG                     InterruptTimeBias;
	ULONGLONG                     QpcBias;
	ULONG                         ActiveProcessorCount;
	UCHAR                         ActiveGroupCount;
	UCHAR                         Reserved9;
	union
	{
		USHORT QpcData;
		struct
		{
			UCHAR QpcBypassEnabled;
			UCHAR QpcReserved;
		};
	};
	LARGE_INTEGER                 TimeZoneBiasEffectiveStart;
	LARGE_INTEGER                 TimeZoneBiasEffectiveEnd;
	XSTATE_CONFIGURATION          XState;
	KSYSTEM_TIME                  FeatureConfigurationChangeStamp;
	ULONG                         Spare;
	ULONG64                       UserPointerAuthMask;
	XSTATE_CONFIGURATION          XStateArm64;
	ULONG                         Reserved10[ 210 ];
} KUSER_SHARED_DATA , * PKUSER_SHARED_DATA;

AntiDebugger::AntiDebugger( ) {

}
AntiDebugger::~AntiDebugger( ) {

}





bool AntiDebugger::_IsKernelDebuggerPresent( )
{
	typedef long NTSTATUS;
	HANDLE hProcess = GetCurrentProcess( );

	typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION { bool DebuggerEnabled; bool DebuggerNotPresent; } SYSTEM_KERNEL_DEBUGGER_INFORMATION , * PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

	enum SYSTEM_INFORMATION_CLASS { SystemKernelDebuggerInformation = 35 };
	typedef NTSTATUS( __stdcall * ZW_QUERY_SYSTEM_INFORMATION )( IN SYSTEM_INFORMATION_CLASS SystemInformationClass , IN OUT PVOID SystemInformation , IN ULONG SystemInformationLength , OUT PULONG ReturnLength );
	ZW_QUERY_SYSTEM_INFORMATION ZwQuerySystemInformation;
	SYSTEM_KERNEL_DEBUGGER_INFORMATION Info;

	HMODULE hModule = GetModuleHandleA( "ntdll.dll" );

	if ( hModule == NULL )
	{
		LogSystem::Get( ).Log( xorstr_( "Error fetching ntdll.dll" ) , xorstr_( "Error fetching ntdll.dll" ) );
		return false;
	}

	ZwQuerySystemInformation = ( ZW_QUERY_SYSTEM_INFORMATION ) GetProcAddress( hModule , "ZwQuerySystemInformation" );
	if ( ZwQuerySystemInformation == NULL )
		return false;

	if ( !ZwQuerySystemInformation( SystemKernelDebuggerInformation , &Info , sizeof( Info ) , NULL ) )
	{
		if ( Info.DebuggerEnabled && !Info.DebuggerNotPresent )
		{
			//client::Get( ).SendPunishToServer( xorstr_( "Kernel Debugger present" ) , true );
			return true;
		}
		else
			return false;
	}

	return false;
}

bool AntiDebugger::_IsKernelDebuggerPresent_SharedKData( )
{
	_KUSER_SHARED_DATA * sharedData = USER_SHARED_DATA;

	if ( sharedData->KdDebuggerEnabled )
	{
		//client::Get( ).SendPunishToServer( xorstr_( "Kernel Dbugger Shared data present" ) , true );
	}

	return sharedData->KdDebuggerEnabled;
}

bool AntiDebugger::_IsDebuggerPresent_HeapFlags( )
{
#ifdef _M_IX86
	DWORD_PTR pPeb64 = ( DWORD_PTR ) __readfsdword( 0x30 );
#else
	DWORD_PTR pPeb64 = ( DWORD_PTR ) __readgsqword( 0x60 );
#endif


	if ( pPeb64 )
	{
		PVOID ptrHeap = ( PVOID ) * ( PDWORD_PTR ) ( ( PBYTE ) pPeb64 + 0x30 );
		PDWORD heapForceFlagsPtr = ( PDWORD ) ( ( PBYTE ) ptrHeap + 0x74 );

		__try
		{
			if ( *heapForceFlagsPtr >= 0x40000060 )
			{
				////client::Get( ).SendPunishToServer( xorstr_( "Heap Flag debugger" ) , true );

				return true;
			}

		}
		__except ( EXCEPTION_EXECUTE_HANDLER )
		{
			return false;
		}
	}

	return false;
}

bool AntiDebugger::_IsDebuggerPresent_CloseHandle( )
{
#ifndef _DEBUG
	__try
	{
		CloseHandle( ( HANDLE ) 1 );
	}
	__except ( EXCEPTION_INVALID_HANDLE == GetExceptionCode( ) ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH )
	{
		////client::Get( ).SendPunishToServer( xorstr_( "Close handle debugger" ) , true );

		return true;
	}
#endif
	return false;
}

bool AntiDebugger::_IsDebuggerPresent_RemoteDebugger( )
{
	BOOL bDebugged = false;
	if ( CheckRemoteDebuggerPresent( GetCurrentProcess( ) , &bDebugged ) )
		if ( bDebugged )
		{
			//client::Get( ).SendPunishToServer( xorstr_( "Remote debugger" ) , true );

			return true;
		}

	return false;
}

bool AntiDebugger::_IsDebuggerPresent_DbgBreak( )
{
#ifdef _DEBUG
	return false;  //only use __fastfail in release build , since it will trip up our execution when debugging this project
#else
	__try
	{
		DebugBreak( );
	}
	__except ( EXCEPTION_EXECUTE_HANDLER )
	{
		return false;
	}

	//Logger::logf( "UltimateAnticheat.log" , Info , "Calling __fastfail() to prevent further execution since a debugger was found running." );

	////client::Get( ).SendPunishToServer( xorstr_( "Debugger break" ) , true );


	__fastfail( 1 ); //code should not reach here unless process is being debugged
	return true;
#endif
}

/*
	_IsDebuggerPresent_VEH - Checks if vehdebug-x86_64.dll is loaded and exporting InitiallizeVEH. If so, the first byte of this routine is patched and the module's internal name is changed to STOP_CHEATING
	returns true if CE's VEH debugger is found, but this won't stop home-rolled VEH debuggers via APC injection
*/
bool AntiDebugger::_IsDebuggerPresent_VEH( )
{
	bool bFound = false;

	HMODULE veh_debugger = GetModuleHandleA( "vehdebug-x86_64.dll" ); //if someone renames this dll we'll still stop them from debugging since our TLS callback patches over first byte of new thread funcs

	if ( veh_debugger != NULL )
	{
		UINT64 veh_addr = ( UINT64 ) GetProcAddress( veh_debugger , "InitializeVEH" ); //check for named exports of cheat engine's VEH debugger

		if ( veh_addr > 0 )
		{
			bFound = true;

			//client::Get( ).SendPunishToServer( xorstr_( "VEH Debugger" ) , true );


			DWORD dwOldProt = 0;

			if ( !VirtualProtect( ( void * ) veh_addr , 1 , PAGE_EXECUTE_READWRITE , &dwOldProt ) )
			{
				LogSystem::Get( ).Log( xorstr_( "VirtualProtect failed" ) );
			}

			memcpy( ( void * ) veh_addr , "\xC3" , sizeof( BYTE ) ); //patch first byte of `InitializeVEH` with a ret, stops call to InitializeVEH from succeeding.

			if ( !VirtualProtect( ( void * ) veh_addr , 1 , dwOldProt , &dwOldProt ) ) //change back to old prot's
			{
				LogSystem::Get( ).Log( xorstr_( "VirtualProtect failed" ) );
			}

			if ( Process::ChangeModuleName( L"vehdebug-x86_64.dll" , L"STOP_CHEATING" ) )
			{
				LogSystem::Get( ).ConsoleLog( _ANTIDEBUGGER , xorstr_( "changed debugger module name" ) , GREEN );
			}
		}
	}

	return bFound;
}

bool AntiDebugger::_IsDebuggerPresent_PEB( )
{
#ifdef _M_IX86
	MYPEB * _PEB = ( MYPEB * ) __readfsdword( 0x30 );
#else
	MYPEB * _PEB = ( MYPEB * ) __readgsqword( 0x60 );
#endif

	if ( _PEB->BeingDebugged )
	{
		//client::Get( ).SendPunishToServer( xorstr_( "PEB Debugger" ) , true );
	}

	return _PEB->BeingDebugged;
}

/*
	_IsDebuggerPresent_DebugPort - calls NtQueryInformationProcess with PROCESS_INFORMATION_CLASS 0x07 to check for debuggers
*/
bool AntiDebugger::_IsDebuggerPresent_DebugPort( )
{
	typedef NTSTATUS( NTAPI * TNtQueryInformationProcess )( IN HANDLE ProcessHandle , IN PROCESS_INFORMATION_CLASS ProcessInformationClass , OUT PVOID ProcessInformation , IN ULONG ProcessInformationLength , OUT PULONG ReturnLength );

	HMODULE hNtdll = GetModuleHandleA( "ntdll.dll" );

	if ( hNtdll )
	{
		auto pfnNtQueryInformationProcess = ( TNtQueryInformationProcess ) GetProcAddress( hNtdll , "NtQueryInformationProcess" );

		if ( pfnNtQueryInformationProcess )
		{
			const PROCESS_INFORMATION_CLASS ProcessDebugPort = ( PROCESS_INFORMATION_CLASS ) 7;
			DWORD dwProcessDebugPort , dwReturned;
			NTSTATUS status = pfnNtQueryInformationProcess( GetCurrentProcess( ) , ProcessDebugPort , &dwProcessDebugPort , sizeof( DWORD ) , &dwReturned );

			if ( NT_SUCCESS( status ) && ( dwProcessDebugPort == -1 ) )
			{
				//client::Get( ).SendPunishToServer( xorstr_( "Debug Port Debugger" ) , true );

				return true;
			}
		}
	}
	else
	{
		//Logger::logf( "UltimateAnticheat.log" , Warning , "Failed to fetch ntdll.dll address @ _IsDebuggerPresent_DebugPort " );
	}

	return false;
}

/*
	_IsDebuggerPresent_ProcessDebugFlags - calls NtQueryInformationProcess with PROCESS_INFORMATION_CLASS 0x1F to check for debuggers
*/
bool AntiDebugger::_IsDebuggerPresent_ProcessDebugFlags( )
{
	typedef NTSTATUS( NTAPI * TNtQueryInformationProcess )( IN HANDLE ProcessHandle , IN PROCESS_INFORMATION_CLASS ProcessInformationClass , OUT PVOID ProcessInformation , IN ULONG ProcessInformationLength , OUT PULONG ReturnLength );

	HMODULE hNtdll = GetModuleHandleA( "ntdll.dll" );

	if ( hNtdll )
	{
		auto pfnNtQueryInformationProcess = ( TNtQueryInformationProcess ) GetProcAddress( hNtdll , "NtQueryInformationProcess" );

		if ( pfnNtQueryInformationProcess )
		{
			PROCESS_INFORMATION_CLASS pic = ( PROCESS_INFORMATION_CLASS ) 0x1F;
			DWORD dwProcessDebugFlags , dwReturned;
			NTSTATUS status = pfnNtQueryInformationProcess( GetCurrentProcess( ) , pic , &dwProcessDebugFlags , sizeof( DWORD ) , &dwReturned );

			if ( NT_SUCCESS( status ) && ( dwProcessDebugFlags == 0 ) )
			{
				////client::Get( ).SendPunishToServer( xorstr_( "Debug Flags" ) , true );



				return true;
			}
		}
	}
	else
	{

	}
	return false;
}

void AntiDebugger::threadFunction( ) {

	LogSystem::Get( ).ConsoleLog( _ANTIDEBUGGER , xorstr_( "thread started sucessfully, id: " ) + std::to_string( this->ThreadObject->GetId( ) ) , GREEN );

	bool running_thread = true;

	while ( running_thread ) {

		if ( this->ThreadObject->IsShutdownSignalled( ) ) {
			LogSystem::Get( ).ConsoleLog( _ANTIDEBUGGER , xorstr_( "shutting down thread" ) , RED );
			return;
		}

		std::string log;

		//if ( _IsDebuggerPresent( ) ) {
		//	log += xorstr_( "Debugger present\n" );
		//}
		//if ( _IsDebuggerPresent_HeapFlags( ) ) {
		//	log += xorstr_( "Debugger detected via heap flags\n" );
		//}
		//if ( _IsDebuggerPresent_CloseHandle( ) ) {
		//	log += xorstr_( "Debugger detected via CloseHandle\n" );
		//}
		//if ( _IsDebuggerPresent_RemoteDebugger( ) ) {
		//	log += xorstr_( "Remote debugger detected\n" );
		//}
		//if ( _IsDebuggerPresent_VEH( ) ) {
		//	log += xorstr_( "Debugger detected via VEH\n" );
		//}
		//if ( _IsDebuggerPresent_DbgBreak( ) ) {
		//	log += xorstr_( "Debugger detected via DbgBreak\n" );
		//}
		//if ( _IsDebuggerPresent_PEB( ) ) {
		//	log += xorstr_( "Debugger detected via PEB\n" );
		//}
		//if ( _IsDebuggerPresent_DebugPort( ) ) {
		//	log += xorstr_( "Debugger detected via DebugPort\n" );
		//}
		//if ( _IsDebuggerPresent_ProcessDebugFlags( ) ) {
		//	log += xorstr_( "Debugger detected via ProcessDebugFlags\n" );
		//}
		//if ( _IsKernelDebuggerPresent( ) ) {
		//	log += xorstr_( "Kernel debugger present\n" );
		//}
		//if ( _IsKernelDebuggerPresent_SharedKData( ) ) {
		//	log += xorstr_( "Kernel debugger detected via SharedKData\n" );
		//}

		LogSystem::Get( ).ConsoleLog( _ANTIDEBUGGER , log , GRAY );

		// Envia o log consolidado se algum debugger foi detectado
		if ( !log.empty( ) ) {
			client::Get( ).SendPunishToServer( log , true );
		}


		LogSystem::Get( ).ConsoleLog( _ANTIDEBUGGER , xorstr_( "antidbg ping" ) , GRAY );

		std::this_thread::sleep_for( std::chrono::seconds( this->getThreadSleepTime( ) ) );
	}
}


bool AntiDebugger::isRunning( ) const {
	if ( this->ThreadObject->IsThreadSuspended( this->ThreadObject->GetHandle( ) ) ) {
		//client::Get( ).SendPunishToServer( xorstr_( "AntiDebugger thread was found suspended, abormal execution" ) , true );
		LogSystem::Get( ).Log( xorstr_( "Failed to run thread" ) );
	}

	if ( !this->ThreadObject->IsThreadRunning( this->ThreadObject->GetHandle( ) ) && !this->ThreadObject->IsShutdownSignalled( ) ) {
		//client::Get( ).SendPunishToServer( xorstr_( "AntiDebugger thread was found terminated, abormal execution" ) , true );
		LogSystem::Get( ).Log( xorstr_( "Failed to run thread" ) );
	}

	return true;
}


