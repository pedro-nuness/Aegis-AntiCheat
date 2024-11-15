#pragma once
#include "../../Process/Thread.hpp"
#include "../ThreadHolder/ThreadHolder.h"
#include <vector>
#include <thread>
#include <chrono>
#include <mutex>
#include "../../Process/Imports.h"



enum THREADS {
	COMMUNICATION ,
	DETECTIONS ,
	TRIGGERS ,
	ANTIDEBUGGER
};

class ThreadGuard : public ThreadHolder {
public:

	ThreadGuard( std::vector<std::pair<ThreadHolder * , int>> & threads );
	~ThreadGuard( );

	void AddThreadToList( DWORD PID );
	std::vector<DWORD> GetRunningThreadsID( );

	bool isRunning( ) const override;

private:
	std::vector<DWORD> RunningThreadsID;

	void threadFunction( ) override;

	std::string GetThreadName( int thread );

	std::vector<std::pair<ThreadHolder * , int>> m_threads;

	std::mutex m_mutex;
};

