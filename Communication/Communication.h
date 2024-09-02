#pragma once
#include <Windows.h>
#include <thread>
#include "../Utils/singleton.h"


enum COMMUNICATION_STATUS {
	NULL_THREAD,
	THREAD_RUNNING,
	THREAD_STOPPING
};

class CommunicationThread {

public:
	HANDLE Handle;
	COMMUNICATION_STATUS CURRENT_STATUS = NULL_THREAD ;
};


class Communication
{
	std::string ProcessName; 
	DWORD ProcessPID; 
	DWORD GamePID; 
	std::string AuthenticMemoryHash;
	std::string ProcessMemoryHash;

	CommunicationThread MonitoringThread;
	CommunicationThread HeartBeatThread;

	static DWORD WINAPI Monitoring( LPVOID param );
public:

	Communication( DWORD Pid, DWORD GamePid ) {
		this->ProcessPID = Pid;
		this->GamePID = GamePid;
	}

	void StartCommunicationThread( );
	

	

};

