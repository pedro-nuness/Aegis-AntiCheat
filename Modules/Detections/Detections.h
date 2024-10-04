#pragma once
#include <Windows.h>
#include <vector>
#include <string>
#include "../ThreadMonitor/ThreadMonitor.h"

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
	std::vector<std::pair<std::string , LPVOID>> data;
};

class Detections : public ThreadMonitor {

	
	std::thread m_thread;
	std::atomic<bool> m_running;
	std::atomic<bool> m_healthy;
	
	bool CalledScanThread = false;
	bool ThreadUpdate = false;

	DWORD MomProcess , ProtectProcess = 0;

	std::string GenerateDetectionStatus( Detection Detect );

	std::vector< Detection > cDetections;

	bool IsDebuggerPresentCustom( );
	void ScanHandles( );
	void ScanWindows( );
	void ScanModules( );
	void AddDetection( Detection d );
	void DigestDetections( );
	void ScanParentModules( );
	void threadFunction( );

	DETECTION_STATUS _status = NOTHING_DETECTED;

public:
	Detections( DWORD _MomProcess , DWORD _ProtectProcess ) {
		this->MomProcess = _MomProcess;
		this->ProtectProcess = _ProtectProcess;
	}

	~Detections( );

	void start( );
	void stop( );

	bool isRunning( ) const override;
	void reset( ) override;
	void requestupdate( ) override;
};

