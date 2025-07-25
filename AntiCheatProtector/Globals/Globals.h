#pragma once
#include <Windows.h>
#include "../Systems/Utils/singleton.h"

#define ALLOCCONSOLE 0

class Globals : public CSingleton<Globals> {

public:
	void * CommunicationObjectPointer;
	bool VerifiedSession = false;
	int AntiCheatPID = 0;
	HMODULE DllModule = NULL;

};