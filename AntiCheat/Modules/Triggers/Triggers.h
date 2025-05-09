#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include "../../Process/Thread.hpp"
#include "../ThreadHolder/ThreadHolder.h"

enum DETECTION_STATUS;

struct Trigger {
	std::string Area;
	std::string Trigger;
	std::string ExpectedTrigger;
	DETECTION_STATUS Status;
};


class Triggers : public ThreadHolder {

	DWORD MomProcess , ProtectProcess;
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

public:
	Triggers ( DWORD _MomProcess , DWORD _ProtectProcess ) 
		: ThreadHolder( THREADS::TRIGGERS )
	{
		SetupFiles( );
		this->MomProcess = _MomProcess;
		this->ProtectProcess = _ProtectProcess;
	}

	~Triggers( );
};

