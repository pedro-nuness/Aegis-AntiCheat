#pragma once
#include <Windows.h>
#include <vector>
#include <string>
#include <unordered_map>

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
	INVALID_THREAD_CREATION,
	IAT_HOOKED
};

class Detections : public ThreadHolder {

	std::mutex AccessGuard;
	std::mutex ExternalDetectionsAcessGuard;

	DWORD MomProcess = 0 , ProtectProcess = 0;
	std::vector<std::string> LoadedDlls;
	std::vector<std::string> PendingLoadedDlls;

	std::vector<std::pair<FLAG_DETECTION , DetectionStruct>> DetectedFlags;
	std::vector<std::pair<FLAG_DETECTION , DetectionStruct>> ExternalDetectedFlags;

	std::vector<DWORD> AllowedThreads;
	bool RegisteredThreads = false;

	bool DoesFunctionAppearHooked( std::string moduleName , std::string functionName, const unsigned char * expectedBytes, bool restore);

	bool IsIATHooked( std::string & moduleName );
	bool IsEATHooked( std::string & moduleName );
	bool InjectProcess( DWORD processId );

	void CheckLoadedDrivers( );
	void CheckLoadedDlls( );
	void CheckOpenHandles( );
	void CheckFunctions( );
	void CheckRunningThreads( );

	void ScanWindows( );
	void ScanModules( );
	void ScanParentModules( );
	void ScanSystemParams( );

	void AddDetection( FLAG_DETECTION flag , DetectionStruct Detect );
	void DigestDetections( );
		 
	std::string GenerateDetectionStatus( FLAG_DETECTION flag , DetectionStruct _detection );

	void threadFunction( ) override;
	static VOID OnDllNotification( ULONG NotificationReason , const PLDR_DLL_NOTIFICATION_DATA NotificationData , PVOID Context );
	std::unordered_map<int , bool> InjectedProcesses;
public:
	void InitializeThreads( );
	void AddThreadToWhitelist( DWORD PID );
	void AddExternalDetection( FLAG_DETECTION , DetectionStruct );
	void SetupPid( DWORD _MomProcess , DWORD _ProtectProcess );

	Detections( );
	~Detections( );

};

