#pragma once
#include "../Systems/Utils/singleton.h"

class Globals : public CSingleton<Globals> {

public:
	void * CommunicationObjectPointer;
	bool VerifiedSession = false;
	int AntiCheatPID = 0;
};