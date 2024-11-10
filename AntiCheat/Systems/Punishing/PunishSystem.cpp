#include "PunishSystem.h"
#include <Windows.h>
#include "../Utils/xorstr.h"
#include "../Utils/utils.h"

void PunishSystem::BanPlayer( ) {
	Utils::Get( ).WarnMessage( _PUNISH , xorstr_( "player banned!" ) , LIGHT_RED );
}

void PunishSystem::UnsafeSession( ) {
	//MessageBoxA( NULL , xorstr_( "AegisUAC has flagged your session as unsafe!\n "), xorstr_( "AegisUAC | pedro.nuness | github/pedro-nuness" ), MB_ICONWARNING );
	Utils::Get( ).WarnMessage( _PUNISH , xorstr_( "unsafe session!" ) , LIGHT_YELLOW );
}

