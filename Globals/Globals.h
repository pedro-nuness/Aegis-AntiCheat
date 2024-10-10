#pragma once
#include <string>
#include "../Systems/Utils/singleton.h"
#include <windows.h>


class Globals : public CSingleton<Globals>
{
public:
	int OriginalProcess;
	int ProtectProcess;
	HWND ProtectProcessHandle = NULL;
	int SelfID; 
	bool VerifiedSession = false;
	std::string UserID;
};

