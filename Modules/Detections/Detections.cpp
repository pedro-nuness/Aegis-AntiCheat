#include "Detections.h"
#include <iostream>
#include <thread>
#include <Windows.h>
#include <unordered_map>

#include "../../Systems/Memory/memory.h"
#include "../../Systems/Utils/xorstr.h"
#include "../../Systems/Monitoring/Monitoring.h"
#include "../../Systems/LogSystem/Log.h"
#include "../../Globals/Globals.h"
#include "../../Systems/Utils/utils.h"
#include "../../Systems/Injection/Injection.h"
#include "../../Client/client.h"



#include "WdkTypes.h"
#include "CtlTypes.h"


#include <dpp/colors.h>
#include <TlHelp32.h>


std::vector<std::string> AllowedMomModules {
		xorstr_( "LauncherTeste.vmp.exe" ),
	xorstr_( "advapi32.dll" ),
	xorstr_( "amsi.dll" ),
	xorstr_( "apphelp.dll" ),
	xorstr_( "bcrypt.dll" ),
	xorstr_( "bcryptprimitives.dll" ),
	xorstr_( "cfgmgr32.dll" ),
	xorstr_( "clbcatq.dll" ),
	xorstr_( "clr.dll" ),
	xorstr_( "clrjit.dll" ),
	xorstr_( "coloradapterclient.dll" ),
	xorstr_( "combase.dll" ),
	xorstr_( "CoreMessaging.dll" ),
	xorstr_( "CoreUIComponents.dll" ),
	xorstr_( "crypt32.dll" ),
	xorstr_( "crypt32.dll.mui" ),
	xorstr_( "cryptbase.dll" ),
	xorstr_( "cryptnet.dll" ),
	xorstr_( "cryptsp.dll" ),
	xorstr_( "d3d11.dll" ),
	xorstr_( "d3d9.dll" ),
	xorstr_( "D3DCompiler_47.dll" ),
	xorstr_( "DataExchange.dll" ),
	xorstr_( "dcomp.dll" ),
	xorstr_( "devobj.dll" ),
	xorstr_( "dhcpcsvc.dll" ),
	xorstr_( "dhcpcsvc6.dll" ),
	xorstr_( "DiscordRPC.dll" ),
	xorstr_( "dnsapi.dll" ),
	xorstr_( "drvstore.dll" ),
	xorstr_( "dwmapi.dll" ),
	xorstr_( "DWrite.dll" ),
	xorstr_( "DXCore.dll" ),
	xorstr_( "dxgi.dll" ),
	xorstr_( "fastprox.dll" ),
	xorstr_( "FWPUCLNT.DLL" ),
	xorstr_( "gdi32.dll" ),
	xorstr_( "gdi32full.dll" ),
	xorstr_( "GdiPlus.dll" ),
	xorstr_( "gpapi.dll" ),
	xorstr_( "icm32.dll" ),
	xorstr_( "iertutil.dll" ),
	xorstr_( "imagehlp.dll" ),
	xorstr_( "imm32.dll" ),
	xorstr_( "IPHLPAPI.DLL" ),
	xorstr_( "kernel.appcore.dll" ),
	xorstr_( "kernel32.dll" ),
	xorstr_( "KernelBase.dll" ),
	xorstr_( "KernelBase.dll.mui" ),
	xorstr_( "locale.nls" ),
	xorstr_( "MpOAV.dll" ),
	xorstr_( "msasn1.dll" ),
	xorstr_( "mscms.dll" ),
	xorstr_( "mscoree.dll" ),
	xorstr_( "mscoreei.dll" ),
	xorstr_( "mscorlib.ni.dll" ),
	xorstr_( "mscorlib.resources.dll" ),
	xorstr_( "mscorrc.dll" ),
	xorstr_( "msctf.dll" ),
	xorstr_( "msctfui.dll" ),
	xorstr_( "msctfui.dll.mui" ),
	xorstr_( "mskeyprotect.dll" ),
	xorstr_( "msvcp140_clr0400.dll" ),
	xorstr_( "msvcp_win.dll" ),
	xorstr_( "msvcrt.dll" ),
	xorstr_( "mswsock.dll" ),
	xorstr_( "NapiNSP.dll" ),
	xorstr_( "ncrypt.dll" ),
	xorstr_( "ncryptsslp.dll" ),
	xorstr_( "netutils.dll" ),
	xorstr_( "Newtonsoft.Json.ni.dll" ),
	xorstr_( "nlaapi.dll" ),
	xorstr_( "nsi.dll" ),
	xorstr_( "ntasn1.dll" ),
	xorstr_( "ntdll.dll" ),
	xorstr_( "ntmarta.dll" ),
	xorstr_( "nvd3dum.dll" ),
	xorstr_( "nvgpucomp32.dll" ),
	xorstr_( "nvldumd.dll" ),
	xorstr_( "nvspcap.dll" ),
	xorstr_( "ole32.dll" ),
	xorstr_( "oleaut32.dll" ),
	xorstr_( "OnDemandConnRouteHelper.dll" ),
	xorstr_( "pnrpnsp.dll" ),
	xorstr_( "powrprof.dll" ),
	xorstr_( "PresentationCore.ni.dll" ),
	xorstr_( "PresentationCore.resources.dll" ),
	xorstr_( "PresentationFramework-SystemXml.dll" ),
	xorstr_( "PresentationFramework.Aero2.ni.dll" ),
	xorstr_( "PresentationFramework.ni.dll" ),
	xorstr_( "PresentationFramework.resources.dll" ),
	xorstr_( "PresentationNative_v0400.dll" ),
	xorstr_( "profapi.dll" ),
	xorstr_( "propsys.dll" ),
	xorstr_( "psapi.dll" ),
	xorstr_( "rasadhlp.dll" ),
	xorstr_( "rasapi32.dll" ),
	xorstr_( "rasman.dll" ),
	xorstr_( "rpcrt4.dll" ),
	xorstr_( "rsaenh.dll" ),
	xorstr_( "rtutils.dll" ),
	xorstr_( "schannel.dll" ),
	xorstr_( "sechost.dll" ),
	xorstr_( "secur32.dll" ),
	xorstr_( "SHCore.dll" ),
	xorstr_( "shell32.dll" ),
	xorstr_( "shlwapi.dll" ),
	xorstr_( "SortDefault.nls" ),
	xorstr_( "srvcli.dll" ),
	xorstr_( "sspicli.dll" ),
	xorstr_( "StaticCache.dat" ),
	xorstr_( "System.Configuration.ni.dll" ),
	xorstr_( "System.Core.ni.dll" ),
	xorstr_( "System.Data.dll" ),
	xorstr_( "System.Data.ni.dll" ),
	xorstr_( "System.Deployment.ni.dll" ),
	xorstr_( "System.Deployment.resources.dll" ),
	xorstr_( "System.Drawing.ni.dll" ),
	xorstr_( "System.Management.ni.dll" ),
	xorstr_( "System.Net.Http.ni.dll" ),
	xorstr_( "System.ni.dll" ),
	xorstr_( "System.Numerics.ni.dll" ),
	xorstr_( "System.resources.dll" ),
	xorstr_( "System.Runtime.Serialization.ni.dll" ),
	xorstr_( "System.Windows.Forms.ni.dll" ),
	xorstr_( "System.Xaml.ni.dll" ),
	xorstr_( "System.Xml.ni.dll" ),
	xorstr_( "TextInputFramework.dll" ),
	xorstr_( "TextShaping.dll" ),
	xorstr_( "twinapi.appcore.dll" ),
	xorstr_( "ucrtbase.dll" ),
	xorstr_( "ucrtbase_clr0400.dll" ),
	xorstr_( "UIAutomationCore.dll" ),
	xorstr_( "UIAutomationProvider.dll" ),
	xorstr_( "UIAutomationTypes.dll" ),
	xorstr_( "umpdc.dll" ),
	xorstr_( "urlmon.dll" ),
	xorstr_( "user32.dll" ),
	xorstr_( "userenv.dll" ),
	xorstr_( "uxtheme.dll" ),
	xorstr_( "vcruntime140_clr0400.dll" ),
	xorstr_( "version.dll" ),
	xorstr_( "wbemcomn.dll" ),
	xorstr_( "wbemprox.dll" ),
	xorstr_( "wbemsvc.dll" ),
	xorstr_( "win32u.dll" ),
	xorstr_( "windows.storage.dll" ),
	xorstr_( "WindowsBase.ni.dll" ),
	xorstr_( "WindowsCodecs.dll" ),
	xorstr_( "WindowsCodecsExt.dll" ),
	xorstr_( "winhttp.dll" ),
	xorstr_( "wininet.dll" ),
	xorstr_( "winmm.dll" ),
	xorstr_( "winnsi.dll" ),
	xorstr_( "winrnr.dll" ),
	xorstr_( "winsta.dll" ),
	xorstr_( "wintrust.dll" ),
	xorstr_( "WinTypes.dll" ),
	xorstr_( "wldp.dll" ),
	xorstr_( "WMINet_Utils.dll" ),
	xorstr_( "wmiutils.dll" ),
	xorstr_( "wow64.dll" ),
	xorstr_( "wow64cpu.dll" ),
	xorstr_( "wow64win.dll" ),
	xorstr_( "wpfgfx_v0400.dll" ),
	xorstr_( "ws2_32.dll" ),
	xorstr_( "wshbth.dll" ),
	xorstr_( "wtsapi32.dll" ),


};



bool Detections::IsDebuggerPresentCustom( ) {
	BOOL isDebuggerPresent = FALSE;
	CheckRemoteDebuggerPresent( GetCurrentProcess( ) , &isDebuggerPresent );
	return isDebuggerPresent || IsDebuggerPresent( );
}

Detections::~Detections( ) {
	stop( );
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
	Utils::Get( ).WarnMessage( _DETECTION  , xorstr_( "resetting thread" ) , YELLOW );
	if ( m_thread.joinable( ) ) {
		m_thread.join( );
	}

	start( );
}

void Detections::requestupdate( ) {
	this->m_healthy = false;
}

std::string Detections::GenerateDetectionStatus( Detection _detection ) {
	std::string _result = "";
	switch ( _detection.status ) {
	case CHEAT_DETECTED:
		_result += xorstr_( "[DETECTION]\n" );
		break;
	case MAY_DETECTED:
		_result += xorstr_( "[SUSPECT]\n" );
		break;

	}

	_result += xorstr_( "Found Infected Process\n" );
	_result += Mem::Get( ).GetProcessName( _detection.ProcessPID ) + xorstr_( "\n" );
	for ( auto module : _detection.ProcessModules ) {
		_result += module + xorstr_( "\n" );
	}

	_result += xorstr_( "\n" );

	return _result;
}

void Detections::AddDetection( Detection d ) {
	cDetections.emplace_back( d );
}

bool IsClear( Detection cd ) {
	return cd.status == NOTHING_DETECTED;
}

void Detections::DigestDetections( ) {
	if ( cDetections.empty( ) ) {
		return;
	}

	cDetections.erase( std::remove_if( cDetections.begin( ) , cDetections.end( ) , IsClear ) , cDetections.end( ) );

	if ( !cDetections.empty( ) ) {
		/*
		* DIGEST DETECTION
		*/
		std::string FinalInfo = "";

		for ( auto Detection : cDetections ) {
			FinalInfo += this->GenerateDetectionStatus( Detection );
		}

		client::Get( ).SendPunishToServer( FinalInfo , true );

	}

	this->cDetections.clear( );
}

void Detections::ScanWindows( ) {
	Utils::Get( ).WarnMessage( _DETECTION  , xorstr_( "starting window scan" ) , GREEN );
	std::unordered_map<DWORD , int> Map;

	// Enumerate all top-level windows
	std::vector<WindowInfo> Windows;
	EnumWindows( Mem::EnumWindowsProc , ( LPARAM ) ( &Windows ) );

	std::unordered_map<HWND , DWORD> DetectedWindows;


	for ( const auto & window : Windows ) {
		if ( window.processId == ( DWORD ) this->MomProcess || window.processId == ( DWORD ) this->ProtectProcess || window.processId == ( DWORD ) Globals::Get( ).SelfID ) {
			continue;
		}

		this->ThreadUpdate = true;

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

				// Compare overlay window and target window rectangles
				// The overlay matches the target window's size and position

				Map[ window.processId ] = true;

				//Backup
				DWORD windowAffinity = NULL;
				if ( !GetWindowDisplayAffinity( window.hwnd , &windowAffinity ) ) {
					continue;
				}

				if ( windowAffinity != WDA_NONE ) {
					Utils::Get( ).WarnMessage( _DETECTION , xorstr_( "got window affinity of id " ) + std::to_string( window.processId ) , GREEN );
					DetectedWindows[ window.hwnd ] = window.processId;
				}
			}
		}
	}

	if ( !DetectedWindows.empty( ) ) {
		std::string Log = "";
		for ( const auto & pair : DetectedWindows ) {
			Injector::Get( ).Inject( xorstr_("windows.dll") , pair.second );
			Log += xorstr_( "Found window allocated on process: " ) + Mem::Get( ).GetProcessExecutablePath( pair.second ) + xorstr_("\n");
		}	

		client::Get( ).SendPunishToServer( Log , false );
		std::this_thread::sleep_for( std::chrono::seconds( 3 ) );
		LogSystem::Get( ).Log( xorstr_( "Unsafe!" ) );
	}


	for ( const auto & pair : Map ) {
		this->ThreadUpdate = true;

		HANDLE hProcess = OpenProcess( PROCESS_VM_READ | PROCESS_QUERY_INFORMATION , FALSE , pair.first );

		if ( hProcess == NULL ) {
			continue;
		}

		std::string ProcessName = Mem::Get( ).GetProcessName( pair.first );

		//Utils::Get( ).WarnMessage( _DETECTION  , xorstr_( "scanning " ) + ProcessName , WHITE );

		Utils::Get( ).WarnMessage( _DETECTION  , xorstr_( "process " ) + ProcessName + xorstr_( " has open window!" ) , YELLOW );


		CloseHandle( hProcess );

	}
	Utils::Get( ).WarnMessage( _DETECTION  , xorstr_( "ending window scan" ) , GREEN );
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

	Utils::Get( ).WarnMessage( _DETECTION  , xorstr_( "scanning modules" ) , WHITE );

	for ( Detection Process : this->cDetections ) {
		this->ThreadUpdate = true;

		std::vector<std::string> InfectedModules;
		switch ( Process.status ) {
		case CHEAT_DETECTED:
			for ( std::string Module : Process.ProcessModules ) {
				this->ThreadUpdate = true;
				uint64_t Address = Mem::Get( ).GetModuleBaseAddress( Module , Process.ProcessPID );
				DWORD ModuleSize = Mem::Get( ).GetModuleSize( Module , Process.ProcessPID );

				if ( !Address || !ModuleSize )
					continue;

				for ( auto Scan : Process.data ) {
					this->ThreadUpdate = true;
					if ( ( uint64_t ) Scan.second >= Address && ( uint64_t ) Scan.second < ( uint64_t ) Address + ( uint64_t ) ModuleSize ) {
						InfectedModules.emplace_back( Module );
						break;
					}
				}
			}
			Process.ProcessModules = InfectedModules;
			break;
		case MAY_DETECTED:
			//? todo
			break;
		default:

			break;
		}
	}
}

void Detections::ScanParentModules( ) {
	std::vector<std::string> MomModules = Mem::Get( ).GetModules( this->MomProcess );

	for ( auto MomModule : MomModules ) {
		bool Found = false;

		for ( auto module : AllowedMomModules ) {
			if ( MomModule == module )
				Found = true;
		}

		if ( !Found ) {
			//AddDetection( Detection { this->MomProcess, xorstr_( "Launcher" ), CHEAT_DETECTED, MomModules } );
		}
	}
}

void Detections::threadFunction( ) {
	Utils::Get( ).WarnMessage( _DETECTION  , xorstr_( "thread started sucessfully\n" ) , GREEN );

	while ( m_running ) {

		Utils::Get( ).WarnMessage( _DETECTION  , xorstr_( "scanning open windows!" ) , GRAY );
		this->ScanWindows( );
		Utils::Get( ).WarnMessage( _DETECTION  , xorstr_( "scanning parent modules!" ) , GRAY );
		this->ScanParentModules( );
		Utils::Get( ).WarnMessage( _DETECTION  , xorstr_( "digesting detections!" ) , GRAY );
		this->DigestDetections( );

		Utils::Get( ).WarnMessage( LIGHT_WHITE , xorstr_( "PING" ) , xorstr_( "detection thread" ) , GRAY );

		m_healthy = true;

		std::this_thread::sleep_for( std::chrono::seconds( 20 ) );
	}
}