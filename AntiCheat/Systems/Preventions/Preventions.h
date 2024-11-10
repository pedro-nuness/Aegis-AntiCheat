#pragma once
#include "../Utils/singleton.h"

class Preventions : public CSingleton<Preventions>
{
public:
	bool RestrictProcessAccess( );
};

