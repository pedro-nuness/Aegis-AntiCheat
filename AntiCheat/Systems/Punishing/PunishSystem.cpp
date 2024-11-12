#include "PunishSystem.h"
#include <Windows.h>
#include "../Utils/xorstr.h"
#include "../LogSystem/Log.h"

void PunishSystem::BanPlayer( ) {
	LogSystem::Get( ).ConsoleLog( _PUNISH , xorstr_( "player banned!" ) , LIGHT_RED );
}

void PunishSystem::UnsafeSession( ) {
	//MessageBoxA( NULL , xorstr_( "AegisUAC has flagged your session as unsafe!\n "), xorstr_( "AegisUAC | pedro.nuness | github/pedro-nuness" ), MB_ICONWARNING );
	LogSystem::Get( ).ConsoleLog( _PUNISH , xorstr_( "unsafe session!" ) , LIGHT_YELLOW );
}

