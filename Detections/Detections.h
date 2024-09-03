#pragma once
#include <Windows.h>
#include <vector>
#include <string>

enum DETECTION_STATUS {
	NOTHING_DETECTED ,
	CHEAT_DETECTED ,
	MAY_DETECTED
};


struct Detection {
	DWORD ProcessPID;
	std::string ProcessName;

	DETECTION_STATUS status;
	std::vector<std::string> ProcessModules;
};


class Detections
{
	DWORD MomProcess , ProtectProcess = 0;
	DETECTION_STATUS _status = NOTHING_DETECTED;
	void InitialThread( );

	DETECTION_STATUS ScanWindows( );
	std::string GenerateDetectionStatus( DWORD PID );
public:
	Detections( DWORD _MomProcess , DWORD _ProtectProcess ) {
		this->MomProcess = _MomProcess;
		this->ProtectProcess = _ProtectProcess;
	}

	void Init( );

	DETECTION_STATUS GetCurrentStatus( ) { return this->_status; };
};

