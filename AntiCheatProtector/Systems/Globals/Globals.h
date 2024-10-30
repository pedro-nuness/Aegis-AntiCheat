#pragma once
#include "../Utils/singleton.h"

class Globals : public CSingleton<Globals> {

public:
	bool VerifiedSession = false;
	int AntiCheatPID = 0;
};