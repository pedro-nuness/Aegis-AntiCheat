#include <Windows.h>
#include "../Utils/singleton.h"

class Security : public CSingleton<Security>
{
public:
	bool CreateThread( void * thread , HMODULE & hModule );

};
