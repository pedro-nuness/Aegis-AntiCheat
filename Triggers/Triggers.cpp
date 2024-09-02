#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <TlHelp32.h>
#include <algorithm>
#include <cctype>
#include <string>


#include "Triggers.h"
#include "../Utils/crypt_str.h"
#include "../Memory/memory.h"
#include "../Utils/utils.h"



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

bool Triggers::Equal( std::vector< Trigger> A , std::vector< Trigger> B ) {

	if ( A.size( ) != B.size( ) ) {
		return false;
	}

	for ( int i = 0; i < A.size( ); i++ ) {
		auto f = A[ i ];
		auto j = B[ i ];

		if ( f.Area != j.Area ) {	
			return false;
		}

		if ( f.ExpectedTrigger != j.ExpectedTrigger ) {
			return false;
		}

		if ( f.Status != j.Status ) {
			return false;
		}

		if ( f.Trigger != j.Trigger ) {
			return false;
		}
	}


	return true;
}

std::vector<Trigger> Triggers::CheckBlackListedProcesses( ) {

	std::vector<Trigger> FoundTriggers;


	for ( auto Process : Mem::Get( ).EnumAllProcesses( ) ) {

		std::transform( Process.begin( ) , Process.end( ) , Process.begin( ) , &Mem::asciitolower );
	
		for ( std::string BLProcess : this->BlackListedProcesses ) {

			std::transform( BLProcess.begin( ) , BLProcess.end( ) , BLProcess.begin( ) , &Mem::asciitolower );

			if ( Utils::Get( ).CheckStrings( BLProcess , Process ) ) {
				FoundTriggers.emplace_back( Trigger { crypt_str( "BlackListedProcess" ) , Process, BLProcess, DETECTED } );
			}
		}
	}

	return FoundTriggers;
}



std::vector<Trigger> Triggers::CheckBlackListedWindows( ) {
	std::vector<Trigger> FoundTriggers;
	for ( auto Window : Mem::Get( ).EnumAllWindows( ) ) {

		std::transform( Window.begin( ) , Window.end( ) , Window.begin( ) , &Mem::asciitolower );

		for ( std::string BLWindow : this->BlackListedWindows ) {

			std::transform( BLWindow.begin( ) , BLWindow.end( ) , BLWindow.begin( ) , &Mem::asciitolower );

			if ( Utils::Get( ).CheckStrings( Window , BLWindow ) ) {
				FoundTriggers.emplace_back( Trigger { crypt_str( "BlackListedWindows" ) ,Window, BLWindow, DETECTED } );
			}
		}
	}

	return FoundTriggers;
}

std::vector<Trigger> Triggers::StartTriggers( ) {

	std::vector<Trigger> Result;

	std::vector<Trigger> SearchProcessResult = CheckBlackListedProcesses( );
	std::vector<Trigger> SearchWindowResult = CheckBlackListedWindows( );

	for ( auto Event : SearchProcessResult ) {
		Result.emplace_back( Event );
	}

	for ( auto Event : SearchWindowResult ) {
		Result.emplace_back( Event );
	}

	if ( !Equal(Result, this->LastTriggers )) { 
		this->LastTriggers = Result;
		return Result;
	}

	return {  };

}