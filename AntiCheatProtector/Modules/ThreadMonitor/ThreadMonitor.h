#pragma once
#include <thread>
#include <atomic>


class ThreadMonitor {
public:
    virtual ~ThreadMonitor( ) {}
    virtual bool isRunning( ) const = 0; // Check if the thread is running correctly
    virtual void reset( ) = 0; // Reset the thread if needed
    virtual void requestupdate( ) = 0;
};