#pragma once
#include "../Systems/Utils/singleton.h"

class Globals : public CSingleton<Globals> {

public:
	bool VerifiedSession = false;
	int AntiCheatPID = 0;
};