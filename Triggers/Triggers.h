#pragma once
#include <string>
#include <vector>

enum STATUS {
	DETECTED,
	CLEAN
};


struct Trigger {
	std::string Area;
	std::string Trigger;
	std::string ExpectedTrigger;
	STATUS Status;
};


class Triggers
{
	std::vector<std::string> BlackListedProcesses;
	std::vector<std::string> BlackListedWindows;
	std::vector<std::string> AllowedModules;

	void SetupFiles( );

	std::vector< Trigger> LastTriggers;
	bool Equal( std::vector< Trigger> A, std::vector< Trigger> B );

public:
	Triggers(  ) {
		SetupFiles( );
	}

	std::vector<Trigger> CheckBlackListedProcesses( );
	std::vector<Trigger> CheckBlackListedWindows( );
	Trigger CheckProcessModules();

	std::vector<Trigger> StartTriggers( );



};

