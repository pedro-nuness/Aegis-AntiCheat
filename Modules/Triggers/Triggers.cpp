#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <TlHelp32.h>
#include <algorithm>
#include <cctype>
#include <string>
#include <thread>

#include "Triggers.h"
#include "../../Systems/Utils/crypt_str.h"
#include "../../Systems/Memory/memory.h"
#include "../../Systems/Utils/utils.h"
#include "../../Systems/Monitoring/Monitoring.h"
#include <dpp/colors.h>



void Triggers::SetupFiles( ) {
	this->BlackListedWindows = {
			crypt_str( "!xSpeed" ),
			crypt_str( "!xSpeed.net" ),
			crypt_str( "!xSpeedPro" ),
			crypt_str( "!xpeed.net" ),
			crypt_str( "99QJ MU Bot" ),
			crypt_str( "AE Bot v1.0 beta" ),
			crypt_str( "AIO Bots" ),
			crypt_str( "Add address" ),
			crypt_str( "ArtMoney PRO" ),
			crypt_str( "ArtMoney SE " ),
			crypt_str( "Auto Combo" ),
			crypt_str( "Auto-Repairer" ),
			crypt_str( "AutoBuff" ),
			crypt_str( "AutoCombo" ),
			crypt_str( "Autoprision" ),
			crypt_str( "Bot MG-DK-ELF" ),
			crypt_str( "Capotecheat" ),
			crypt_str( "Capotecheat(deltacholl)" ),
			crypt_str( "Catastrophe" ),
			crypt_str( "Chaos Bot" ),
			crypt_str( "CharBlaster" ),
			crypt_str( "CharEditor" ),
			crypt_str( "Cheat Engine" ),
			crypt_str( "Cheat Happens " ),
			crypt_str( "Cheat Master" ),
			crypt_str( "Cheat4Fun" ),
			crypt_str( "Codehitcz" ),
			crypt_str( "Created processes" ),
			crypt_str( "D-C Bypass" ),
			crypt_str( "D-C DupeHack" ),
			crypt_str( "D-C Master Inject" ),
			crypt_str( "DC Mu" ),
			crypt_str( "DC-BYPASS" ),
			crypt_str( "DK(AE)MultiStrikeByDude" ),
			crypt_str( "DarkCheats Mu Ar" ),
			crypt_str( "DarkLord Bot" ),
			crypt_str( "DarkyStats (www.darkhacker.com.ar)" ),
			crypt_str( "Dizzys Auto Buff" ),
			crypt_str( "Dupe-Full" ),
			crypt_str( "Easy As MuPie" ),
			crypt_str( "Esperando Mu Online" ),
			crypt_str( "FunnyZhyper" ),
			crypt_str( "Game Speed Adjuster" ),
			crypt_str( "Game Speed Changer" ),
			crypt_str( "GodMode" ),
			crypt_str( "Godlike" ),
			crypt_str( "HahaMu" ) ,
			crypt_str( "Hasty MU" ) ,
			crypt_str( "HastyMU" ) ,
			crypt_str( "HideToolz" ) ,
			crypt_str( "Hit Count" ) ,
			crypt_str( "Hit Hack" ) ,
			crypt_str( "Injector" ) ,
			crypt_str( "Janopn Mini Multi Cheat" ) ,
			crypt_str( "Jewel Drop Beta" ) ,
			crypt_str( "JoyToKey" ) ,
			crypt_str( "Lipsum" ) ,
			crypt_str( "Load File" ) ,
			crypt_str( "MJB Perfect DL Bot" ) ,
			crypt_str( "MLEngine" ) ,
			crypt_str( "MU Lite Trainer" ) ,
			crypt_str( "MU Utilidades" ) ,
			crypt_str( "MU-SS4 Speed Hack" ) ,
			crypt_str( "MUSH" ) ,
			crypt_str( "Minimize" ) ,
			crypt_str( "ModzMu" ) ,
			crypt_str( "MoonLight" ) ,
			crypt_str( "Mu Cheater 16" ) ,
			crypt_str( "Mu Philiphinas Cheat II" ) ,
			crypt_str( "Mu Pie Beta" ) ,
			crypt_str( "Mu Pirata MMHack" ) ,
			crypt_str( "Mu proxy" ) ,
			crypt_str( "MuBot" ) ,
			crypt_str( "MuCheat" ) ,
			crypt_str( "MuHackRm" ) ,
			crypt_str( "MuOnline Speed Hack" ) ,
			crypt_str( "MuPie HG" ) ,
			crypt_str( "MuPieHG" ) ,
			crypt_str( "MuPieX" ) ,
			crypt_str( "MuPie_v2Beta" ) ,
			crypt_str( "MuProxy" ) ,
			crypt_str( "Mugster Bot" ) ,
			crypt_str( "Mupie Minimizer" ) ,
			crypt_str( "Mush" ) ,
			crypt_str( "NoNameMini" ) ,
			crypt_str( "Olly Debugger" ) ,
			crypt_str( "Overclock Menu" ) ,
			crypt_str( "Perfect AutoPotion" ) ,
			crypt_str( "Permit" ) ,
			crypt_str( "PeruCheats" ) ,
			crypt_str( "ProxCheatsX 2.0 - Acacias" ) ,
			crypt_str( "Razor Code Only" ) ,
			crypt_str( "Razor Code" ) ,
			crypt_str( "Snd Bot" ) ,
			crypt_str( "Speed Gear" ) ,
			crypt_str( "Speed Hack" ) ,
			crypt_str( "Speed Hacker" ) ,
			crypt_str( "SpeedGear" ) ,
			crypt_str( "SpeedMUVN" ) ,
			crypt_str( "SpiffsAutobot" ) ,
			crypt_str( "SpotHack" ) ,
			crypt_str( "Super Bot" ) ,
			crypt_str( "T Search" ) ,
			crypt_str( "Tablet 2" ) ,
			crypt_str( "The following opcodes accessed the selected address" ) ,
			crypt_str( "Trade HACK" ) ,
			crypt_str( "Ultimate Cheat" ) ,
			crypt_str( "UoPilot" ) ,
			crypt_str( "VaultBlaster" ) ,
			crypt_str( "VaultEditor (www.darkhacker.com.ar)" ) ,
			crypt_str( "WPE PRO" ) ,
			crypt_str( "WPePro" ) ,
			crypt_str( "WildProxy" ) ,
			crypt_str( "Xelerator" ) ,
			crypt_str( "ZhyperMu Packet Editor" ) ,
			crypt_str( "[Dark-Cheats]" ) ,
			crypt_str( "eXpLoRer" ) ,
			crypt_str( "hacker" ) ,
			crypt_str( "rPE - rEdoX Packet Editor" ) ,
			crypt_str( "razorcode" ) ,
			crypt_str( "speednet" ) ,
			crypt_str( "speednet2" ) ,
			crypt_str( "www.55xp.com" ) ,
			crypt_str( "BVKHEX" ) ,
			crypt_str( "OllyDbg" ) ,
			crypt_str( "HxD" ) ,
			crypt_str( "BY DARKTERRO" ) ,
			crypt_str( "Tim Geimi Jaks - DarkTerro" ) ,
			crypt_str( "PROCEXPL" ) ,             // Process explorer
			crypt_str( "ProcessHacker" ) ,        // Process Hacker	
			crypt_str( "PhTreeNew" ) ,            // Process Hacker (Process windows)
			crypt_str( "RegEdit_RegEdit" ) ,      // Regedit
			crypt_str( "0x150114 (1376532)" ) ,   // Win 7 - System configuration
			crypt_str( "SysListView32" ) ,        // Lista de processos do process explorer
			crypt_str( "TformSettings" ) ,
			crypt_str( "Afx:400000:8:10011:0:20575" ) ,
			crypt_str( "TWildProxyMain" ) ,
			crypt_str( "TUserdefinedform" ) ,
			crypt_str( "TformAddressChange" ) ,
			crypt_str( "TMemoryBrowser" ) ,
			crypt_str( "TFoundCodeDialog" ) ,
			crypt_str( "IDA" ),
			crypt_str( "DnSpy" ),
			crypt_str( "cheat" )
	};

	this->BlackListedProcesses = {
		crypt_str( "ahk.exe" ),
		crypt_str( "ida.exe" ),
		crypt_str( "ollydbg.exe*32" ),
		crypt_str( "ollydbg.exe" ),
		crypt_str( "bvkhex.exe" ),
		crypt_str( "cheatengine-x86_64.exe" ),
		crypt_str( "HxD.exe" ),
		crypt_str( "procexp2.exe" ),
		crypt_str( "Hide Toolz3.3.3.exe" ),
		crypt_str( "SbieSvc.exe" ),    // < sandbox 
		crypt_str( "SbieSvc*32.exe" ), // < sandbox 
		crypt_str( "SbieSvc*32.exe" ), // < sandbox 
		crypt_str( "SbieCtrl.exe" ),
		crypt_str( "ProcessHacker.exe" )
	};
}


Triggers::~Triggers( ) {
	stop( );
}

void Triggers::start( ) {
	m_running = true;
	m_thread = std::thread( &Triggers::threadFunction , this );
}

void Triggers::stop( ) {
	m_running = false;
	if ( m_thread.joinable( ) ) {
		m_thread.join( );
	}
}

bool Triggers::isRunning( ) const {
	return m_running && m_healthy;
}

void Triggers::requestupdate( ) {
	this->m_healthy = false;
}

void Triggers::reset( ) {
	std::cout << crypt_str( "[TRIGGERS] resetting thread!\n" );
	// Implementation to reset the thread
	if ( m_thread.joinable( ) ) {
		m_thread.join( );
	}
	
	start( );
}

bool Triggers::AreTriggersEqual( const Trigger & t1 , const Trigger & t2 ) {
	return t1.Area == t2.Area &&
		t1.Trigger == t2.Trigger &&
		t1.ExpectedTrigger == t2.ExpectedTrigger &&
		t1.Status == t2.Status;
}

bool CompareTriggers( const Trigger & t1 , const Trigger & t2 ) {
	if ( t1.Area != t2.Area ) return t1.Area < t2.Area;
	if ( t1.Trigger != t2.Trigger ) return t1.Trigger < t2.Trigger;
	if ( t1.ExpectedTrigger != t2.ExpectedTrigger ) return t1.ExpectedTrigger < t2.ExpectedTrigger;
	return t1.Status < t2.Status;
}

// Função para remover duplicatas de um vetor de Trigger
void Triggers::RemoveDuplicates( std::vector<Trigger> & triggers ) {
	// Sort the vector of triggers to bring duplicates together
	std::sort( triggers.begin( ) , triggers.end( ) , CompareTriggers );

	// Use std::unique to move duplicates to the end, keeping the first occurrence
	auto lastUnique = std::unique( triggers.begin( ) , triggers.end( ) , [ ] ( const Trigger & t1 , const Trigger & t2 ) {
		return t1.Area == t2.Area &&
			t1.Trigger == t2.Trigger &&
			t1.ExpectedTrigger == t2.ExpectedTrigger &&
			t1.Status == t2.Status;
		} );

	// Resize the vector to remove the duplicate entries
	triggers.erase( lastUnique , triggers.end( ) );
}

std::vector<Trigger> Triggers::GetDifferent( std::vector< Trigger> A , std::vector< Trigger> B ) {

	std::vector<Trigger> result;

	for ( const auto & triggerB : B ) {
		bool found = false;

		for ( const auto & triggerA : A ) {
			if ( AreTriggersEqual( triggerB , triggerA ) ) {
				found = true;
				break;
			}
		}

		if ( !found ) {
			result.push_back( triggerB );
		}
	}

	return result;
}

void Triggers::AddTrigger( Trigger Tr ) {
	this->FoundTriggers.emplace_back( Tr );
}


void Triggers::DigestTriggers( ) {

	if ( this->FoundTriggers.empty( ) )
		return;

	RemoveDuplicates( this->FoundTriggers );

	std::vector<Trigger> NewTriggers = GetDifferent( this->LastTriggers , this->FoundTriggers );

	if ( !NewTriggers.empty( ) ) {
		Monitoring::Get( ).SendInfo( GenerateWarningStatus( NewTriggers ), dpp::colors::yellow, true  );
		std::cout << GenerateWarningStatus(NewTriggers ) << "\n";
	}

	this->LastTriggers = this->FoundTriggers;
}

void Triggers::CheckBlackListedProcesses( ) {
	for ( auto Process : Mem::Get( ).EnumAllProcesses( ) ) {
		DWORD PID = Mem::Get( ).GetProcessID( Process.c_str( ));
		if ( PID == this->MomProcess || PID == this->ProtectProcess ) 
			continue;
		std::this_thread::sleep_for( std::chrono::milliseconds( 50 ) );

		std::transform( Process.begin( ) , Process.end( ) , Process.begin( ) , &Mem::asciitolower );
	
		for ( std::string BLProcess : this->BlackListedProcesses ) {

			std::transform( BLProcess.begin( ) , BLProcess.end( ) , BLProcess.begin( ) , &Mem::asciitolower );

			if ( Utils::Get( ).CheckStrings( BLProcess , Process ) ) {
				AddTrigger( Trigger { crypt_str( "BlackListedProcess" ) , Process, BLProcess, WARNING } );
			}
		}
	}
}

void Triggers::CheckBlackListedWindows( ) {
	std::vector<Trigger> FoundTriggers;
	for ( auto Window : Mem::Get( ).EnumAllWindows( ) ) {
		std::this_thread::sleep_for( std::chrono::milliseconds( 50 ) );
		std::transform( Window.begin( ) , Window.end( ) , Window.begin( ) , &Mem::asciitolower );

		for ( std::string BLWindow : this->BlackListedWindows ) {

			std::transform( BLWindow.begin( ) , BLWindow.end( ) , BLWindow.begin( ) , &Mem::asciitolower );

			if ( Utils::Get( ).CheckStrings( Window , BLWindow ) ) {
				AddTrigger( Trigger { crypt_str( "BlackListedWindows" ) ,Window, BLWindow, WARNING } );
			}
		}
	}
}

std::string Triggers::GenerateWarningStatus(std::vector<Trigger> Triggers ) {
	std::string STR = crypt_str("[WARNING] Found Malicious process!\n\n");
	for ( auto T : Triggers ) {
		STR += T.Trigger + crypt_str("\n\n");
	}
	return STR;
}

void Triggers::threadFunction( ) {
	std::cout << crypt_str( "[TRIGGERS] starting thread!\n" );
	while ( m_running ) {
		m_healthy = true;
		this->CheckBlackListedProcesses( );
		this->CheckBlackListedWindows( );

		this->DigestTriggers( );

		std::this_thread::sleep_for( std::chrono::seconds( 15 ) );
	}
}