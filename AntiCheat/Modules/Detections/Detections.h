#pragma once
#include <Windows.h>
#include <vector>
#include <string>

#include "../../Obscure/ntldr.h"
#include "../../Process/Thread.hpp"
#include "../ThreadHolder/ThreadHolder.h"


#include <mutex>

enum DETECTION_STATUS;


struct DetectionStruct {
	DetectionStruct( std::string _Log, DETECTION_STATUS status) {
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
	FUNCTION_HOOKED,
	OPENHANDLE_TO_US,
};

class Detections : public ThreadHolder {

	std::mutex AccessGuard;

	DWORD MomProcess = 0 , ProtectProcess = 0;
	std::vector<std::string> LoadedDlls;
	std::vector<std::string> PendingLoadedDlls;

	std::vector<std::pair<FLAG_DETECTION , DetectionStruct>> DetectedFlags;

	std::vector<DWORD> AllowedThreads;
	bool RegisteredThreads = false;

	bool DoesFunctionAppearHooked( std::string moduleName , std::string functionName, const unsigned char * expectedBytes );

	bool IsIATHooked( std::string & moduleName );
	bool IsEATHooked( std::string & moduleName );

	void CheckLoadedDrivers( );
	void CheckLoadedDlls( );
	void CheckOpenHandles( );
	void CheckFunctions( );
	void CheckRunningThreads( );

	void ScanWindows( );
	void ScanModules( );
	void ScanParentModules( );

	void AddDetection( FLAG_DETECTION flag , DetectionStruct Detect );
	void DigestDetections( );
	


	 
	std::string GenerateDetectionStatus( FLAG_DETECTION flag , DetectionStruct _detection );

	void threadFunction( ) override;
	static VOID OnDllNotification( ULONG NotificationReason , const PLDR_DLL_NOTIFICATION_DATA NotificationData , PVOID Context );



public:
	void InitializeThreads( );
	void AddThreadToWhitelist( DWORD PID );
	void SetupPid( DWORD _MomProcess , DWORD _ProtectProcess );

	Detections( );
	~Detections( );

	bool isRunning( ) const override;
};

