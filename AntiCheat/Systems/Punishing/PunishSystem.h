#pragma once
#include "../Utils/singleton.h"

class PunishSystem : public CSingleton<PunishSystem>
{
public:
	void BanPlayer( );
	void UnsafeSession( );

};

