#pragma once
#include <Windows.h>
#include <string>
#include <vector>

enum STATUS {
	DETECTED,
	WARNING,
	CLEAN,
};


struct Trigger {
	std::string Area;
	std::string Trigger;
	std::string ExpectedTrigger;
	STATUS Status;
};


class Triggers
{
	DWORD MomProcess , ProtectProcess;
	std::vector<std::string> BlackListedProcesses;
	std::vector<std::string> BlackListedWindows;
	std::vector<std::string> AllowedModules;

	void SetupFiles( );

	std::vector< Trigger> LastTriggers;
	bool Equal( std::vector< Trigger> A, std::vector< Trigger> B );

	std::string GenerateWarningStatus( std::vector<Trigger> Triggers );
public:
	Triggers ( DWORD _MomProcess , DWORD _ProtectProcess ) {
		SetupFiles( );
		this->MomProcess = _MomProcess;
		this->ProtectProcess = _ProtectProcess;
	}

	std::vector<Trigger> CheckBlackListedProcesses( );
	std::vector<Trigger> CheckBlackListedWindows( );
	Trigger CheckProcessModules();


	std::vector<Trigger> StartTriggers( );




};

