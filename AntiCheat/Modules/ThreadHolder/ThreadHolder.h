#pragma once
#include <thread>
#include <atomic>
#include <string>

#include "../../Process/Thread.hpp"

enum THREAD_STATUS {
    NO_STATUS,
    INITIALIZATION_FAILED,
    SUSPENDED,
    TERMINATED
};


enum THREADS {
    TRIGGERS ,
    DETECTIONS ,
    COMMUNICATION ,
    ANTIDEBUGGER ,
    LISTENER,
    THREADGUARD,
    NO_THREAD
};

class ThreadHolder {
protected:
    // Wrapper function for the thread function to be implemented in derived classes
    static void threadFunctionWrapper( LPVOID instance );
   

private:
    int SleepTime = 10;
    THREAD_STATUS threadStatus = THREAD_STATUS::NO_STATUS;
    THREADS ThreadTypeID = NO_THREAD;


    virtual void threadFunction( ) = 0;
public:
    static std::string GetThreadName( THREADS thread );
    static std::string StatusToString( THREAD_STATUS status );
    static void initializeThreadWaiter( );

    void waitOtherThreads( );

    std::unique_ptr<Thread> ThreadObject;
    
    bool ThreadStarted = false;

    virtual ~ThreadHolder( ) { stop( ); }
    ThreadHolder( THREADS id ) : ThreadTypeID( id ) {}

    virtual THREADS getThreaID( ) const { return ThreadTypeID; }

    virtual void start( );

    virtual void stop( );

    virtual void reset( );

    virtual THREAD_STATUS isRunning( );

    virtual int getThreadSleepTime( ) const { return SleepTime; }  // Default sleep time

    THREAD_STATUS getThreadStatus( ) {
        return this->threadStatus;
    }

    void setThreadStatus( THREAD_STATUS status ) {
        this->threadStatus = status;
    }
};