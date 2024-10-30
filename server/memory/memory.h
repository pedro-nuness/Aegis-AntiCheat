#pragma once
#include <string>
#include <windows.h>

#include "../utils/singleton.h"

class memory : public CSingleton<memory>
{
public:


	std::string GetProcessPath( DWORD processID );
	
};

