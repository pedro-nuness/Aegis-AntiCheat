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


class Detections:  public ThreadHolder
{
	void threadFunction( ) override;	
	

	void CheckHandles( );
	bool InjectProcess( DWORD processId );  
	void RemoveInjection( DWORD processId );
	void CheckInjectedProcesses( );

	std::unordered_map<int, bool> InjectedProcesses;
public:
	Detections( );
	~Detections( );

	bool isRunning( ) const override;
};

