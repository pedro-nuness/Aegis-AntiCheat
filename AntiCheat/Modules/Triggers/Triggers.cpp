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


#include "../../Systems/Utils/StringCrypt/StringCrypt.h"
#include "../ThreadGuard/ThreadGuard.h"


std::vector<CryptedString> BlackListedProcesses;
std::vector<CryptedString> BlackListedWindows;


void Triggers::SetupFiles( ) {
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "!xSpeed" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "!xSpeed.net" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "!xSpeedPro" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "!xpeed.net" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "99QJ MU Bot" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "AE Bot v1.0 beta" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "AIO Bots" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "Add address" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "ArtMoney PRO" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "ArtMoney SE" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "AutoKey" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "AVBot" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "AutoHack" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "BanList" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "BattleEye" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "Blackhawk Cheats" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "BotNet" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "Chams" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "Cheat Engine" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "CheatHelper" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "Cheatster" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "ChronicBot" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "ClubDark Bot" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "CopyCat" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "CPUAwareBot" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "CraftBot" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "DarkBot" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "Darkhook" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "DBot" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "EasyBot" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "ESP Tools" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "FakeCheat" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "FinalBot" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "FreeBot" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "GameHax" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "GamerBot" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "Hack Pro" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "Hacknet" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "Hackster" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "Injector" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "InternalBot" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "KillerBot" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "NoCheat" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "OBot" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "PerfectCheat" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "PopBot" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "QuickHack" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "QuickInjector" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "RageBot" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "SpeedHack" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "StealthBot" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "StenCheat" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "SuperBot" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "TBot" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "TestBot" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "UltimateBot" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "UndetectedBot" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "UnlimitedBot" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "VIPBot" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "X-Bot" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "XpertBot" ) ) );
	BlackListedWindows.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "ZBot" ) ) );

	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "ahk.exe" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "ida.exe" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "ollydbg" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "bvkhex.exe" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "cheat" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "HxD.exe" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "procexp2.exe" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "Hide Toolz3.3.3.exe" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "SbieSvc.exe" ) ) );  // < sandbox
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "SbieSvc*32.exe" ) ) ); // < sandbox
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "ProcessHacker.exe" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "injector" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "hack" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "wireshark" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "wireshark" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "fiddler.exe" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "charles.exe" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "mitmproxy.exe" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "mbot.exe" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "x32dbg.exe" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "x64dbg.exe" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "UnrealCheat.exe" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "PSExec.exe" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "injector" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "Antivirus" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "keylogger.exe" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "vncviewer.exe" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "TeamViewer.exe" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "VmWare.exe" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "Sandboxie.exe" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "spybot.exe" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "Wireshark.exe" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "fiddler.exe" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "charles.exe" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "mitmproxy.exe" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "mbot.exe" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "x32dbg.exe" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "x64dbg.exe" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "UnrealCheat.exe" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "PSExec.exe" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "injector" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "Antivirus" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "keylogger.exe" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "vncviewer.exe" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "TeamViewer.exe" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "VmWare.exe" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "Sandboxie.exe" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "NoCheatExe" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "GenericBot.exe" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "CheatProcessor.exe" ) ) );
	BlackListedProcesses.emplace_back( StringCrypt::Get( ).EncryptString( xorstr_( "DebugBot.exe" ) ) );
}


Triggers::~Triggers( ) {
	stop( );
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
		_client.SendPunishToServer( GenerateWarningStatus( NewTriggers ) , WARN );
	}

	this->LastTriggers = this->FoundTriggers;
}

void Triggers::CheckBlackListedProcesses( ) {
	for ( auto Process : Mem::Get( ).EnumAllProcesses( ) ) {
		DWORD PID = Mem::Get( ).GetProcessID( Process.c_str( ) );
		if ( PID == this->MomProcess || PID == this->ProtectProcess || PID == _globals.SelfID )
			continue;
		std::this_thread::sleep_for( std::chrono::milliseconds( 50 ) );

		std::transform( Process.begin( ) , Process.end( ) , Process.begin( ) , &Mem::asciitolower );


		for ( auto & BLProcess : BlackListedProcesses ) {

			std::string * DecryptedString = StringCrypt::Get( ).DecryptString( BLProcess );

			std::transform( DecryptedString->begin( ) , DecryptedString->end( ) , DecryptedString->begin( ) , &Mem::asciitolower );

			if ( Utils::Get( ).CheckStrings( *DecryptedString , Process ) ) {
				AddTrigger( Trigger { xorstr_( "BlackListedProcess" ) , Process, *DecryptedString, SUSPECT } );
				LogSystem::Get( ).ConsoleLog( _TRIGGERS , xorstr_( "found black listed process: " ) + Process , YELLOW );
			}

			StringCrypt::Get( ).CleanString( DecryptedString );

		}
	}
}

void Triggers::CheckBlackListedWindows( ) {
	std::vector<Trigger> FoundTriggers;
	for ( auto Window : Mem::Get( ).EnumAllWindows( ) ) {
		std::this_thread::sleep_for( std::chrono::milliseconds( 1 ) );
		std::transform( Window.begin( ) , Window.end( ) , Window.begin( ) , &Mem::asciitolower );

		for ( auto & BLWindow : BlackListedWindows ) {

			std::string * DecryptedString = StringCrypt::Get( ).DecryptString( BLWindow );

			std::transform( DecryptedString->begin( ) , DecryptedString->end( ) , DecryptedString->begin( ) , &Mem::asciitolower );

			if ( Utils::Get( ).CheckStrings( Window , *DecryptedString ) ) {
				AddTrigger( Trigger { xorstr_( "BlackListedWindows" ) ,Window, *DecryptedString, SUSPECT } );
				LogSystem::Get( ).ConsoleLog( _TRIGGERS , xorstr_( "found black listed window: " ) + Window , YELLOW );
			}

			StringCrypt::Get( ).CleanString( DecryptedString );
		}
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

void Triggers::threadFunction( ) {

	{
		std::lock_guard<std::mutex> lock( _globals.threadReadyMutex );
		_globals.threadsReady.at( THREADS::TRIGGERS ) = true;
		LogSystem::Get( ).ConsoleLog( _TRIGGERS , xorstr_( "thread signalled ready!" ) , GREEN );
	}

	while ( true ) {
		std::vector<bool> localthreadsReady;
		{
			std::lock_guard<std::mutex> lock( _globals.threadReadyMutex );
			localthreadsReady = _globals.threadsReady;
		}

		bool found = false;

		for ( int i = 0; i < localthreadsReady.size( ); i++ ) {
			if ( !localthreadsReady.at( i ) ) {
				found = true;
				break;
			}
		}

		if ( !found ) {
			break;
		}
	}

	bool Run = true;
	LogSystem::Get( ).ConsoleLog( _TRIGGERS , xorstr_( "thread started sucessfully, id: " ) + std::to_string( this->ThreadObject->GetId( ) ) , GREEN );

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