#pragma once
#include <string>
#include "../Systems/Utils/singleton.h"



class Globals : public CSingleton<Globals>
{
public:
	int OriginalProcess;
	int ProtectProcess;
	int SelfID;
	bool VerifiedSession = false;
	std::string UserID;
};

