#pragma once
#include <thread>
#include <atomic>
#include "../../Process/Thread.hpp"

class ThreadHolder {
protected:
    // Wrapper function for the thread function to be implemented in derived classes
    static void threadFunctionWrapper( LPVOID instance );

private:
    

    virtual void threadFunction( ) = 0;
public:
    std::unique_ptr<Thread> ThreadObject;

    virtual ~ThreadHolder( ) { stop( ); }

    virtual void start( );

    virtual void stop( );

    virtual void reset( );

    virtual bool isRunning( ) const = 0;

    virtual int getThreadSleepTime( ) const { return 5; }  // Default sleep time
};