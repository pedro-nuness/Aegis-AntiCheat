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

#include "../../Systems/LogSystem/Log.h"
#include "../../Systems/Utils/xorstr.h"
#include "../../Systems/Memory/memory.h"
#include "../../Systems/Utils/utils.h"
#include "../../Systems/Monitoring/Monitoring.h"
#include "../../Systems/Punishing/PunishSystem.h"
#include "../../Client/client.h"
#include "../../Globals/Globals.h"



void Triggers::CleanFiles( ) {
	std::fill( this->BlackListedProcesses.begin( ) , this->BlackListedProcesses.end( ) , "" );
	this->BlackListedProcesses.clear( );

	std::fill( this->BlackListedProcesses.begin( ) , this->BlackListedProcesses.end( ) , "" );
	this->BlackListedProcesses.clear( );
}

void Triggers::SetupFiles( ) {
	this->BlackListedWindows = {
			xorstr_( "!xSpeed" ),
			xorstr_( "!xSpeed.net" ),
			xorstr_( "!xSpeedPro" ),
			xorstr_( "!xpeed.net" ),
			xorstr_( "99QJ MU Bot" ),
			xorstr_( "AE Bot v1.0 beta" ),
			xorstr_( "AIO Bots" ),
			xorstr_( "Add address" ),
			xorstr_( "ArtMoney PRO" ),
			xorstr_( "ArtMoney SE " ),
			xorstr_( "Auto Combo" ),
			xorstr_( "Auto-Repairer" ),
			xorstr_( "AutoBuff" ),
			xorstr_( "AutoCombo" ),
			xorstr_( "Autoprision" ),
			xorstr_( "Bot MG-DK-ELF" ),
			xorstr_( "Capotecheat" ),
			xorstr_( "Capotecheat(deltacholl)" ),
			xorstr_( "Catastrophe" ),
			xorstr_( "Chaos Bot" ),
			xorstr_( "CharBlaster" ),
			xorstr_( "CharEditor" ),
			xorstr_( "Cheat Engine" ),
			xorstr_( "Cheat Happens " ),
			xorstr_( "Cheat Master" ),
			xorstr_( "Cheat4Fun" ),
			xorstr_( "Codehitcz" ),
			xorstr_( "Created processes" ),
			xorstr_( "D-C Bypass" ),
			xorstr_( "D-C DupeHack" ),
			xorstr_( "D-C Master Inject" ),
			xorstr_( "DC Mu" ),
			xorstr_( "DC-BYPASS" ),
			xorstr_( "DK(AE)MultiStrikeByDude" ),
			xorstr_( "DarkCheats Mu Ar" ),
			xorstr_( "DarkLord Bot" ),
			xorstr_( "DarkyStats (www.darkhacker.com.ar)" ),
			xorstr_( "Dizzys Auto Buff" ),
			xorstr_( "Dupe-Full" ),
			xorstr_( "Easy As MuPie" ),
			xorstr_( "Esperando Mu Online" ),
			xorstr_( "FunnyZhyper" ),
			xorstr_( "Game Speed Adjuster" ),
			xorstr_( "Game Speed Changer" ),
			xorstr_( "GodMode" ),
			xorstr_( "Godlike" ),
			xorstr_( "HahaMu" ) ,
			xorstr_( "Hasty MU" ) ,
			xorstr_( "HastyMU" ) ,
			xorstr_( "HideToolz" ) ,
			xorstr_( "Hit Count" ) ,
			xorstr_( "Hit Hack" ) ,
			xorstr_( "Injector" ) ,
			xorstr_( "Janopn Mini Multi Cheat" ) ,
			xorstr_( "Jewel Drop Beta" ) ,
			xorstr_( "JoyToKey" ) ,
			xorstr_( "Lipsum" ) ,
			xorstr_( "Load File" ) ,
			xorstr_( "MJB Perfect DL Bot" ) ,
			xorstr_( "MLEngine" ) ,
			xorstr_( "MU Lite Trainer" ) ,
			xorstr_( "MU Utilidades" ) ,
			xorstr_( "MU-SS4 Speed Hack" ) ,
			xorstr_( "MUSH" ) ,
			xorstr_( "Minimize" ) ,
			xorstr_( "ModzMu" ) ,
			xorstr_( "MoonLight" ) ,
			xorstr_( "Mu Cheater 16" ) ,
			xorstr_( "Mu Philiphinas Cheat II" ) ,
			xorstr_( "Mu Pie Beta" ) ,
			xorstr_( "Mu Pirata MMHack" ) ,
			xorstr_( "Mu proxy" ) ,
			xorstr_( "MuBot" ) ,
			xorstr_( "MuCheat" ) ,
			xorstr_( "MuHackRm" ) ,
			xorstr_( "MuOnline Speed Hack" ) ,
			xorstr_( "MuPie HG" ) ,
			xorstr_( "MuPieHG" ) ,
			xorstr_( "MuPieX" ) ,
			xorstr_( "MuPie_v2Beta" ) ,
			xorstr_( "MuProxy" ) ,
			xorstr_( "Mugster Bot" ) ,
			xorstr_( "Mupie Minimizer" ) ,
			xorstr_( "Mush" ) ,
			xorstr_( "NoNameMini" ) ,
			xorstr_( "Olly Debugger" ) ,
			xorstr_( "Overclock Menu" ) ,
			xorstr_( "Perfect AutoPotion" ) ,
			xorstr_( "Permit" ) ,
			xorstr_( "PeruCheats" ) ,
			xorstr_( "ProxCheatsX 2.0 - Acacias" ) ,
			xorstr_( "Razor Code Only" ) ,
			xorstr_( "Razor Code" ) ,
			xorstr_( "Snd Bot" ) ,
			xorstr_( "Speed Gear" ) ,
			xorstr_( "Speed Hack" ) ,
			xorstr_( "Speed Hacker" ) ,
			xorstr_( "SpeedGear" ) ,
			xorstr_( "SpeedMUVN" ) ,
			xorstr_( "SpiffsAutobot" ) ,
			xorstr_( "SpotHack" ) ,
			xorstr_( "Super Bot" ) ,
			xorstr_( "T Search" ) ,
			xorstr_( "Tablet 2" ) ,
			xorstr_( "The following opcodes accessed the selected address" ) ,
			xorstr_( "Trade HACK" ) ,
			xorstr_( "Ultimate Cheat" ) ,
			xorstr_( "UoPilot" ) ,
			xorstr_( "VaultBlaster" ) ,
			xorstr_( "VaultEditor (www.darkhacker.com.ar)" ) ,
			xorstr_( "WPE PRO" ) ,
			xorstr_( "WPePro" ) ,
			xorstr_( "WildProxy" ) ,
			xorstr_( "Xelerator" ) ,
			xorstr_( "ZhyperMu Packet Editor" ) ,
			xorstr_( "[Dark-Cheats]" ) ,
			xorstr_( "eXpLoRer" ) ,
			xorstr_( "hacker" ) ,
			xorstr_( "rPE - rEdoX Packet Editor" ) ,
			xorstr_( "razorcode" ) ,
			xorstr_( "speednet" ) ,
			xorstr_( "speednet2" ) ,
			xorstr_( "www.55xp.com" ) ,
			xorstr_( "BVKHEX" ) ,
			xorstr_( "OllyDbg" ) ,
			xorstr_( "HxD" ) ,
			xorstr_( "BY DARKTERRO" ) ,
			xorstr_( "Tim Geimi Jaks - DarkTerro" ) ,
			xorstr_( "PROCEXPL" ) ,             // Process explorer
			xorstr_( "ProcessHacker" ) ,        // Process Hacker	
			xorstr_( "PhTreeNew" ) ,            // Process Hacker (Process windows)
			xorstr_( "RegEdit_RegEdit" ) ,      // Regedit
			xorstr_( "0x150114 (1376532)" ) ,   // Win 7 - System configuration
			xorstr_( "SysListView32" ) ,        // Lista de processos do process explorer
			xorstr_( "TformSettings" ) ,
			xorstr_( "Afx:400000:8:10011:0:20575" ) ,
			xorstr_( "TWildProxyMain" ) ,
			xorstr_( "TUserdefinedform" ) ,
			xorstr_( "TformAddressChange" ) ,
			xorstr_( "TMemoryBrowser" ) ,
			xorstr_( "TFoundCodeDialog" ) ,
			xorstr_( "IDA" ),
			xorstr_( "DnSpy" ),
			xorstr_( "cheat" )
	};

	this->BlackListedProcesses = {
		xorstr_( "ahk.exe" ),
		xorstr_( "ida.exe" ),
		xorstr_( "ollydbg" ),
		xorstr_( "bvkhex.exe" ),
		xorstr_( "cheat" ),
		xorstr_( "HxD.exe" ),
		xorstr_( "procexp2.exe" ),
		xorstr_( "Hide Toolz3.3.3.exe" ),
		xorstr_( "SbieSvc.exe" ),    // < sandbox 
		xorstr_( "SbieSvc*32.exe" ), // < sandbox 
		xorstr_( "SbieSvc*32.exe" ), // < sandbox 
		xorstr_( "SbieCtrl.exe" ),
		xorstr_( "ProcessHacker.exe" ),
		xorstr_( "injector" ),
		xorstr_( "hack" ),
		xorstr_( "wireshark" ),
	};
}


Triggers::~Triggers( ) {
	stop( );
}


bool Triggers::isRunning( ) const {
	if ( this->ThreadObject->IsThreadSuspended( this->ThreadObject->GetHandle( ) ) ) {
		client::Get( ).SendPunishToServer( xorstr_( "Triggers thread was found suspended, abormal execution" ) , true );
		LogSystem::Get( ).Log( xorstr_( "Failed to run thread" ) );
	}

	if ( !this->ThreadObject->IsThreadRunning( this->ThreadObject->GetHandle( ) ) && !this->ThreadObject->IsShutdownSignalled( ) ) {
		client::Get( ).SendPunishToServer( xorstr_( "Triggers thread was found terminated, abormal execution" ) , true );
		LogSystem::Get( ).Log( xorstr_( "Failed to run thread" ) );
	}

	return true;
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
		client::Get( ).SendPunishToServer( GenerateWarningStatus( NewTriggers ) , false );
		LogSystem::Get( ).LogWithMessageBox( xorstr_( "Unsafe" ) , xorstr_( "unsafe session" ) );
	}

	this->LastTriggers = this->FoundTriggers;
}

void Triggers::CheckBlackListedProcesses( ) {
	for ( auto Process : Mem::Get( ).EnumAllProcesses( ) ) {
		DWORD PID = Mem::Get( ).GetProcessID( Process.c_str( ) );
		if ( PID == this->MomProcess || PID == this->ProtectProcess || PID == Globals::Get( ).SelfID )
			continue;
		std::this_thread::sleep_for( std::chrono::milliseconds( 50 ) );

		std::transform( Process.begin( ) , Process.end( ) , Process.begin( ) , &Mem::asciitolower );

		this->SetupFiles( );

		for ( std::string BLProcess : this->BlackListedProcesses ) {

			std::transform( BLProcess.begin( ) , BLProcess.end( ) , BLProcess.begin( ) , &Mem::asciitolower );

			if ( Utils::Get( ).CheckStrings( BLProcess , Process ) ) {
				AddTrigger( Trigger { xorstr_( "BlackListedProcess" ) , Process, BLProcess, SUSPECT } );
				LogSystem::Get( ).ConsoleLog( _TRIGGERS , xorstr_( "found black listed process: " ) + Process , YELLOW );
			}
		}

		this->CleanFiles( );
	}
}

void Triggers::CheckBlackListedWindows( ) {
	std::vector<Trigger> FoundTriggers;
	for ( auto Window : Mem::Get( ).EnumAllWindows( ) ) {
		std::this_thread::sleep_for( std::chrono::milliseconds( 1 ) );
		std::transform( Window.begin( ) , Window.end( ) , Window.begin( ) , &Mem::asciitolower );

		this->SetupFiles( );

		for ( std::string BLWindow : this->BlackListedWindows ) {

			std::transform( BLWindow.begin( ) , BLWindow.end( ) , BLWindow.begin( ) , &Mem::asciitolower );

			if ( Utils::Get( ).CheckStrings( Window , BLWindow ) ) {
				AddTrigger( Trigger { xorstr_( "BlackListedWindows" ) ,Window, BLWindow, SUSPECT } );
				LogSystem::Get( ).ConsoleLog( _TRIGGERS , xorstr_( "found black listed window: " ) + Window , YELLOW );
			}
		}

		this->CleanFiles( );
	}
}

std::string Triggers::GenerateWarningStatus( std::vector<Trigger> Triggers ) {
	std::string STR; ;
	for ( auto T : Triggers ) {
		STR += xorstr_( "** Found Malicious process!**\n" );
		STR += xorstr_( "- " ) + T.Trigger + xorstr_( "\n\n" );
	}
	return STR;
}

void Triggers::threadFunction(  ) {

	bool Run = true;
	LogSystem::Get( ).ConsoleLog( _TRIGGERS , xorstr_( "thread started sucessfully, id: " ) + std::to_string( this->ThreadObject->GetId( ) ) , GREEN );

	while ( !Globals::Get( ).VerifiedSession ) {
		if ( this->ThreadObject->IsShutdownSignalled( ) ) {
			LogSystem::Get( ).ConsoleLog( _TRIGGERS , xorstr_( "shutting down thread" ) , RED );
			return;
		}
		//as fast as possible cuh
		std::this_thread::sleep_for( std::chrono::nanoseconds( 1 ) ); // Check every 30 seconds
	}

	while ( Run ) {

		if ( this->ThreadObject->IsShutdownSignalled( ) ) {
			LogSystem::Get( ).ConsoleLog( _TRIGGERS , xorstr_( "shutting down thread" ) , RED );
			return;
		}

		this->CheckBlackListedProcesses( );
		this->CheckBlackListedWindows( );

		this->DigestTriggers( );

		std::this_thread::sleep_for( std::chrono::seconds( this->getThreadSleepTime( ) ) );
	}
}