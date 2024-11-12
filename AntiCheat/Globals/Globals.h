#pragma once
#include <string>
#include "../Systems/Utils/singleton.h"
#include <windows.h>


enum DETECTION_STATUS {
	NOTHING_DETECTED ,
	DETECTED ,
	SUSPECT
};

class Globals : public CSingleton<Globals>
{
public:
	int OriginalProcess;
	int ProtectProcess;
	int SelfID;

	void * GuardMonitorPointer;

	bool VerifiedSession = false;

	std::string Nickname;
	std::string NicknameHash;

	std::string CLIENT_NAME;
	std::string DUMPER_NAME;
};

