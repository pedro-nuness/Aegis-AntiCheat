#pragma once

#include "ThreadMonitor.h"
#include <vector>
#include <thread>
#include <chrono>
#include <mutex>


enum THREADS {
    COMMUNICATION,
    DETECTIONS,
    TRIGGERS
};

class MonitorThread : public ThreadMonitor {
public:
    MonitorThread( std::vector<std::pair<ThreadMonitor*, int>> & threads );
    ~MonitorThread( );

    void start( );
    void stop( );

    bool isRunning( ) const override;
    void reset( ) override;
    void requestupdate( ) override;

private:
    void monitorFunction( );

    std::string GetThreadName( int thread );

    std::vector<std::pair<ThreadMonitor * , int>> m_threads;
    std::thread m_thread;
    std::atomic<bool> m_running;
    bool healthy;
    std::mutex m_mutex;
};

