#include "Detections.h"
#include <iostream>
#include <thread>
#include <Windows.h>
#include <unordered_map>

#include "../../Systems/Memory/memory.h"
#include "../../Systems/Utils/crypt_str.h"
#include "../../Systems/Monitoring/Monitoring.h"
#include "../../Systems/LogSystem/Log.h"
#include "../../Globals/Globals.h"

#include <dpp/colors.h>

#define timepoint std::chrono::steady_clock::time_point
#define now std::chrono::high_resolution_clock::now()

std::vector<std::string> AllowedMomModules {
		crypt_str( "LauncherTeste.vmp.exe" ),
	crypt_str( "advapi32.dll" ),
	crypt_str( "amsi.dll" ),
	crypt_str( "apphelp.dll" ),
	crypt_str( "bcrypt.dll" ),
	crypt_str( "bcryptprimitives.dll" ),
	crypt_str( "cfgmgr32.dll" ),
	crypt_str( "clbcatq.dll" ),
	crypt_str( "clr.dll" ),
	crypt_str( "clrjit.dll" ),
	crypt_str( "coloradapterclient.dll" ),
	crypt_str( "combase.dll" ),
	crypt_str( "CoreMessaging.dll" ),
	crypt_str( "CoreUIComponents.dll" ),
	crypt_str( "crypt32.dll" ),
	crypt_str( "crypt32.dll.mui" ),
	crypt_str( "cryptbase.dll" ),
	crypt_str( "cryptnet.dll" ),
	crypt_str( "cryptsp.dll" ),
	crypt_str( "d3d11.dll" ),
	crypt_str( "d3d9.dll" ),
	crypt_str( "D3DCompiler_47.dll" ),
	crypt_str( "DataExchange.dll" ),
	crypt_str( "dcomp.dll" ),
	crypt_str( "devobj.dll" ),
	crypt_str( "dhcpcsvc.dll" ),
	crypt_str( "dhcpcsvc6.dll" ),
	crypt_str( "DiscordRPC.dll" ),
	crypt_str( "dnsapi.dll" ),
	crypt_str( "drvstore.dll" ),
	crypt_str( "dwmapi.dll" ),
	crypt_str( "DWrite.dll" ),
	crypt_str( "DXCore.dll" ),
	crypt_str( "dxgi.dll" ),
	crypt_str( "fastprox.dll" ),
	crypt_str( "FWPUCLNT.DLL" ),
	crypt_str( "gdi32.dll" ),
	crypt_str( "gdi32full.dll" ),
	crypt_str( "GdiPlus.dll" ),
	crypt_str( "gpapi.dll" ),
	crypt_str( "icm32.dll" ),
	crypt_str( "iertutil.dll" ),
	crypt_str( "imagehlp.dll" ),
	crypt_str( "imm32.dll" ),
	crypt_str( "IPHLPAPI.DLL" ),
	crypt_str( "kernel.appcore.dll" ),
	crypt_str( "kernel32.dll" ),
	crypt_str( "KernelBase.dll" ),
	crypt_str( "KernelBase.dll.mui" ),
	crypt_str( "locale.nls" ),
	crypt_str( "MpOAV.dll" ),
	crypt_str( "msasn1.dll" ),
	crypt_str( "mscms.dll" ),
	crypt_str( "mscoree.dll" ),
	crypt_str( "mscoreei.dll" ),
	crypt_str( "mscorlib.ni.dll" ),
	crypt_str( "mscorlib.resources.dll" ),
	crypt_str( "mscorrc.dll" ),
	crypt_str( "msctf.dll" ),
	crypt_str( "msctfui.dll" ),
	crypt_str( "msctfui.dll.mui" ),
	crypt_str( "mskeyprotect.dll" ),
	crypt_str( "msvcp140_clr0400.dll" ),
	crypt_str( "msvcp_win.dll" ),
	crypt_str( "msvcrt.dll" ),
	crypt_str( "mswsock.dll" ),
	crypt_str( "NapiNSP.dll" ),
	crypt_str( "ncrypt.dll" ),
	crypt_str( "ncryptsslp.dll" ),
	crypt_str( "netutils.dll" ),
	crypt_str( "Newtonsoft.Json.ni.dll" ),
	crypt_str( "nlaapi.dll" ),
	crypt_str( "nsi.dll" ),
	crypt_str( "ntasn1.dll" ),
	crypt_str( "ntdll.dll" ),
	crypt_str( "ntdll.dll" ),
	crypt_str( "ntmarta.dll" ),
	crypt_str( "nvd3dum.dll" ),
	crypt_str( "nvgpucomp32.dll" ),
	crypt_str( "nvldumd.dll" ),
	crypt_str( "nvspcap.dll" ),
	crypt_str( "ole32.dll" ),
	crypt_str( "oleaut32.dll" ),
	crypt_str( "OnDemandConnRouteHelper.dll" ),
	crypt_str( "pnrpnsp.dll" ),
	crypt_str( "powrprof.dll" ),
	crypt_str( "PresentationCore.ni.dll" ),
	crypt_str( "PresentationCore.resources.dll" ),
	crypt_str( "PresentationFramework-SystemXml.dll" ),
	crypt_str( "PresentationFramework.Aero2.ni.dll" ),
	crypt_str( "PresentationFramework.ni.dll" ),
	crypt_str( "PresentationFramework.resources.dll" ),
	crypt_str( "PresentationNative_v0400.dll" ),
	crypt_str( "profapi.dll" ),
	crypt_str( "propsys.dll" ),
	crypt_str( "psapi.dll" ),
	crypt_str( "rasadhlp.dll" ),
	crypt_str( "rasapi32.dll" ),
	crypt_str( "rasman.dll" ),
	crypt_str( "rpcrt4.dll" ),
	crypt_str( "rsaenh.dll" ),
	crypt_str( "rtutils.dll" ),
	crypt_str( "schannel.dll" ),
	crypt_str( "sechost.dll" ),
	crypt_str( "secur32.dll" ),
	crypt_str( "SHCore.dll" ),
	crypt_str( "shell32.dll" ),
	crypt_str( "shlwapi.dll" ),
	crypt_str( "SortDefault.nls" ),
	crypt_str( "srvcli.dll" ),
	crypt_str( "sspicli.dll" ),
	crypt_str( "StaticCache.dat" ),
	crypt_str( "System.Configuration.ni.dll" ),
	crypt_str( "System.Core.ni.dll" ),
	crypt_str( "System.Data.dll" ),
	crypt_str( "System.Data.ni.dll" ),
	crypt_str( "System.Deployment.ni.dll" ),
	crypt_str( "System.Deployment.resources.dll" ),
	crypt_str( "System.Drawing.ni.dll" ),
	crypt_str( "System.Management.ni.dll" ),
	crypt_str( "System.Net.Http.ni.dll" ),
	crypt_str( "System.ni.dll" ),
	crypt_str( "System.Numerics.ni.dll" ),
	crypt_str( "System.resources.dll" ),
	crypt_str( "System.Runtime.Serialization.ni.dll" ),
	crypt_str( "System.Windows.Forms.ni.dll" ),
	crypt_str( "System.Xaml.ni.dll" ),
	crypt_str( "System.Xml.ni.dll" ),
	crypt_str( "TextInputFramework.dll" ),
	crypt_str( "TextShaping.dll" ),
	crypt_str( "twinapi.appcore.dll" ),
	crypt_str( "ucrtbase.dll" ),
	crypt_str( "ucrtbase_clr0400.dll" ),
	crypt_str( "UIAutomationCore.dll" ),
	crypt_str( "UIAutomationProvider.dll" ),
	crypt_str( "UIAutomationTypes.dll" ),
	crypt_str( "umpdc.dll" ),
	crypt_str( "urlmon.dll" ),
	crypt_str( "user32.dll" ),
	crypt_str( "userenv.dll" ),
	crypt_str( "uxtheme.dll" ),
	crypt_str( "vcruntime140_clr0400.dll" ),
	crypt_str( "version.dll" ),
	crypt_str( "wbemcomn.dll" ),
	crypt_str( "wbemprox.dll" ),
	crypt_str( "wbemsvc.dll" ),
	crypt_str( "win32u.dll" ),
	crypt_str( "windows.storage.dll" ),
	crypt_str( "WindowsBase.ni.dll" ),
	crypt_str( "WindowsCodecs.dll" ),
	crypt_str( "WindowsCodecsExt.dll" ),
	crypt_str( "winhttp.dll" ),
	crypt_str( "wininet.dll" ),
	crypt_str( "winmm.dll" ),
	crypt_str( "winnsi.dll" ),
	crypt_str( "winrnr.dll" ),
	crypt_str( "winsta.dll" ),
	crypt_str( "wintrust.dll" ),
	crypt_str( "WinTypes.dll" ),
	crypt_str( "wldp.dll" ),
	crypt_str( "WMINet_Utils.dll" ),
	crypt_str( "wmiutils.dll" ),
	crypt_str( "wow64.dll" ),
	crypt_str( "wow64cpu.dll" ),
	crypt_str( "wow64win.dll" ),
	crypt_str( "wpfgfx_v0400.dll" ),
	crypt_str( "ws2_32.dll" ),
	crypt_str( "wshbth.dll" ),
	crypt_str( "wtsapi32.dll" ),
};

timepoint LastFullScan = now - std::chrono::duration( std::chrono::seconds( 100 ) );
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
	std::cout << crypt_str( "[detection] resetting thread!\n" );
	if ( m_thread.joinable( ) ) {
		m_thread.join( );
	}

	start( );
}

void Detections::requestupdate( ) {
	this->m_healthy = false;
}

std::string Detections::GenerateDetectionStatus(Detection _detection) {
	std::string _result = "";
	switch ( _detection.status ) {
	case CHEAT_DETECTED:
		_result += crypt_str( "[DETECTION]\n" );
		break;
	case MAY_DETECTED:
		_result += crypt_str( "[SUSPECT]\n" );
		break;

	}

	_result += crypt_str( "Found Infected Process\n" );
	_result += Mem::Get( ).GetProcessName( _detection.ProcessPID ) + crypt_str( "\n" );
	for ( auto module : _detection.ProcessModules ) {
		_result += module + crypt_str( "\n" );
	}

	_result += crypt_str( "\n" );

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

		Monitoring::Get( ).SendInfo( FinalInfo , dpp::colors::red , true );
	}

	this->cDetections.clear( );
}

void Detections::ScanWindows( ) {
	std::cout << crypt_str( "[detection] Starting Window scan!\n" );
	std::unordered_map<DWORD , int> Map;

	// Enumerate all top-level windows
	std::vector<WindowInfo> Windows;
	EnumWindows( Mem::EnumWindowsProc , ( LPARAM ) ( &Windows ) );

	for ( const auto & window : Windows ) {
		if ( window.processId == this->MomProcess || window.processId == this->ProtectProcess ) {
			continue;
		}

		this->ThreadUpdate = true;

		// Check for overlay characteristics
		LONG_PTR exStyle = GetWindowLongPtr( window.hwnd , GWL_EXSTYLE );
		if ( exStyle & WS_EX_LAYERED | WS_EX_TRANSPARENT ) {
			if ( Map[ window.processId ] ) {
				continue;
			}
			Map[ window.processId ]++;
		}
	}

	for ( const auto & pair : Map ) {
		this->ThreadUpdate = true;

		std::this_thread::sleep_for( std::chrono::milliseconds( 250 ) );

		std::string ProcessName = Mem::Get( ).GetProcessName( pair.first );
		std::cout << "[SCAN]: " << ProcessName << "\n";

		HANDLE hProcess = OpenProcess( PROCESS_VM_READ | PROCESS_QUERY_INFORMATION , FALSE , pair.first );

		if ( hProcess == NULL ) {
			continue;
		}

		std::vector<std::string> TargetStrings {
				crypt_str( "Aimbot" ),
				crypt_str( "Box" ),
				crypt_str( "Skeleton" ),
				crypt_str( "Distance" ),
				crypt_str( "ESP" ),
				crypt_str( "Hack" ),
				crypt_str( "Entities" ),
				crypt_str( "dayzinfected" ),
				crypt_str( "clothing" ),
				crypt_str( "dayzplayer" ),
				crypt_str( "dayzanimal" ),
				crypt_str( "inventoryItem" ),
				crypt_str( "ProxyMagazines" ),
				crypt_str( "Weapon" ),
				crypt_str( "DayZ_x64.exe" )
		};

		std::vector<MemoryRegion> memoryDump;

		if ( Mem::Get( ).DumpProcessMemory( hProcess , memoryDump ) ) {

			this->ThreadUpdate = true;

			if ( memoryDump.empty( ) ) {
				CloseHandle( hProcess );
				continue;
			}

			std::vector<std::pair<std::string , LPVOID>> Founds = Mem::Get( ).SearchStringsInDump( memoryDump , TargetStrings );

			if ( ( float ) Founds.size( ) / ( float ) TargetStrings.size( ) > 0.7 ) {
				std::cout << crypt_str( "[DETECTION] Found Infected Process: " ) << Mem::Get( ).GetProcessName( pair.first ) << "\n";
				AddDetection( Detection { pair.first, ProcessName, CHEAT_DETECTED, Mem::Get( ).GetModules( pair.first ), Founds } );
				CloseHandle( hProcess );
				continue;
			}

			AddDetection( Detection { pair.first, ProcessName, NOTHING_DETECTED, Mem::Get( ).GetModules( pair.first ), Founds } );
		}

		CloseHandle( hProcess );

	}
	std::cout << crypt_str( "[detection] Ending Window scan!\n" );
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

	std::cout << crypt_str( "[detection] Scanning Modules\n" );

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
						std::cout << "[MODULE SCAN] Infected Module: " << Module << "\n";
						break;
					}
				}
			}
			Process.ProcessModules = InfectedModules;
			break;

		default:
			
			break;
		}
	}

	//Reset thread call timer
	LastFullScan = now;
	this->CalledScanThread = false;
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
			AddDetection( Detection { this->MomProcess, crypt_str( "Launcher" ), CHEAT_DETECTED, MomModules } );
		}
	}
}

void Detections::threadFunction( ) {
	std::cout << crypt_str( "[detection] thread started sucessfully!\n" );
	while ( m_running  ) {

		
		if ( this->CalledScanThread ) {
			if ( this->ThreadUpdate ) {
				this->ThreadUpdate = false;
				//Thread answer
			}
			else {
				//Thread stopped answer!
				std::cout << "[detection] Thread stopped, anomaly detected!\n";
				AddDetection( Detection { 0, crypt_str( "Scan Thread Stopped" ), CHEAT_DETECTED, {} } );
				this->CalledScanThread = false;
				this->DigestDetections( );
			}
		}
		else {
			std::cout << crypt_str( "[detection] Scanning parent modules!\n" );
			this->ScanParentModules( );

			std::cout << crypt_str( "[detection] Digesting detections!\n" );
			this->DigestDetections( );
		}

		std::chrono::duration<double> elapsed = now - LastFullScan;
		if ( elapsed.count( ) >= 100 && !this->CalledScanThread ) {
			std::cout << crypt_str( "[detection] Scanning Windows\n" );
			std::thread( &Detections::ScanWindows , this ).detach( );
			this->CalledScanThread = true;
		}

		
		std::cout << crypt_str( "[detection] Ping!\n" );

		m_healthy = true;

		std::this_thread::sleep_for( std::chrono::seconds( 20 ) );
	}
}