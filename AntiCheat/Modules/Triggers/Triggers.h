#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include "../../Process/Thread.hpp"
#include "../ThreadHolder/ThreadHolder.h"

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

class Triggers : public ThreadHolder {

	DWORD MomProcess , ProtectProcess;
	std::vector<std::string> BlackListedProcesses;
	std::vector<std::string> BlackListedWindows;
	std::vector<std::string> AllowedModules;

	void SetupFiles( );
	void CleanFiles( );


	std::vector< Trigger> FoundTriggers;
	std::vector< Trigger> LastTriggers;

	void RemoveDuplicates( std::vector<Trigger> & triggers );

	void AddTrigger( Trigger  Tr );
	void DigestTriggers( );
	std::vector<Trigger> GetDifferent( std::vector< Trigger> A, std::vector< Trigger> B );
	bool AreTriggersEqual( const Trigger & t1 , const Trigger & t2 );
	std::string GenerateWarningStatus( std::vector<Trigger> Triggers );

	void CheckBlackListedProcesses( );
	void CheckBlackListedWindows( );
	void threadFunction( ) override;

	std::thread m_thread;
	std::atomic<bool> m_running;
	std::atomic<bool> m_healthy;

public:
	Triggers ( DWORD _MomProcess , DWORD _ProtectProcess ) {
		this->MomProcess = _MomProcess;
		this->ProtectProcess = _ProtectProcess;
	}

	~Triggers( );

	bool isRunning( ) const override;
};

