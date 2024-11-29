#pragma once
#include "../ThreadHolder/ThreadHolder.h"
#include <string>
#include <vector>
#include <windows.h>
#include <unordered_map>

enum DETECTION_STATUS {
	NOTHING_DETECTED ,
	DETECTED ,
	SUSPECT
};


struct DetectionStruct {
	DetectionStruct( std::string _Log , DETECTION_STATUS status ) {
		this->Log = _Log;
		this->_Status = status;
	}

	DETECTION_STATUS _Status;
	std::string Log;
};

enum FLAG_DETECTION {
	UNVERIFIED_DRIVER_RUNNING ,
	UNVERIFIED_MODULE_LOADED ,
	SUSPECT_WINDOW_OPEN ,
	HIDE_FROM_CAPTURE_WINDOW ,
	FUNCTION_HOOKED ,
	OPENHANDLE_TO_US ,
};


class Detections:  public ThreadHolder
{
	void threadFunction( ) override;	
	
	std::vector<std::pair<FLAG_DETECTION , DetectionStruct>> DetectedFlags;
	bool DoesFunctionAppearHooked( std::string moduleName , std::string functionName , const unsigned char * expectedBytes );
	void CheckFunctions( );
	void CheckHandles( );
	bool InjectProcess( DWORD processId );  
	void RemoveInjection( DWORD processId );
	void CheckInjectedProcesses( );

	void AddDetection( FLAG_DETECTION flag , DetectionStruct Detect );
	void DigestDetections( );

	std::string GenerateDetectionStatus( FLAG_DETECTION flag , DetectionStruct _detection );

	std::unordered_map<int, bool> InjectedProcesses;
public:
	Detections( );
	~Detections( );

	bool isRunning( ) const override;
};

