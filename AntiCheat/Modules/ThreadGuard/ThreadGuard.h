#pragma once
#include "../../Process/Thread.hpp"
#include "../ThreadHolder/ThreadHolder.h"
#include <vector>
#include <thread>
#include <chrono>
#include <mutex>


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

	int RunningThreads( ) { return this->m_threads.size( ); }
	HANDLE  GetThread( int i );

	bool IsThreadrunning( int i );

	bool isRunning( ) const override;

private:
	void threadFunction( ) override;

	std::string GetThreadName( int thread );

	std::vector<std::pair<ThreadHolder * , int>> m_threads;

	std::mutex m_mutex;
};

