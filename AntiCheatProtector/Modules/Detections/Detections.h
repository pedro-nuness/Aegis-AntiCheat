#pragma once
#include "../ThreadMonitor/ThreadMonitor.h"
#include <string>
#include <vector>
#include <windows.h>
#include <unordered_map>

class Detections:  public ThreadMonitor
{
	void threadFunction( );
	void KeepThreadAlive( );

	std::thread m_thread;
	std::atomic<bool> m_running;
	std::atomic<bool> m_healthy;

	void DetectMemoryPermissions( );
	void DetectUnknownModules( );
	bool CheckCriticalFunctionRedirects( std::string funcName );
	bool DetectTrampolines( FARPROC func , const BYTE * expectedBytes , SIZE_T length );
	void CheckDynamicModules( );
	void MonitorExternalProcesses( );
	void RunDetections( );

	void CheckHandles( );
	void CheckThreads( );
	bool ScanCurrentThreads( );

	bool InjectProcess( DWORD processId );  
	void RemoveInjection( DWORD processId );
	void CheckInjectedProcesses( );

	std::unordered_map<int, bool> InjectedProcesses;
public:
	Detections( );
	~Detections( );

	void start( );
	void stop( );


	bool isRunning( ) const override;
	void reset( ) override;
	void requestupdate( ) override;
};

