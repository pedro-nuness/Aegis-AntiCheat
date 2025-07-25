#pragma once
#include <string>
#include <vector>
#include <mutex>

#include "../Systems/Utils/singleton.h"
#include "../Systems/RegeditFiles/regFiles.h"

#include <windows.h>

enum DETECTION_STATUS {
	NOTHING_DETECTED ,
	DETECTED ,
	SUSPECT
};

class Globals
{
public:
	DWORD OriginalProcess;
	DWORD ProtectProcess;
	DWORD SelfID;

	void * GuardMonitorPointer;
	void * DetectionsPointer;
	void * TriggersPointer;
	void * AntiDebuggerPointer;

	std::string GeneralUID;

	bool RequestedScreenshot = false;
	bool LoggedIn = false;

	std::string Nickname;
	std::string NicknameHash;
	std::string OriginalProcessHash;
	std::string GameName;
	std::string ModuleName;

	std::string CLIENT_NAME;
	std::string DUMPER_NAME;

	HMODULE dllModule;

	std::vector<std::uint8_t> encryptedDumper;
};

extern regFiles _regfiles;
extern Globals _globals;

