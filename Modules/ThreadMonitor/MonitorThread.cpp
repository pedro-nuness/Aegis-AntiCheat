#include "MonitorThread.h"
#include <iostream>

#include "../../Systems/Utils/crypt_str.h"

MonitorThread::MonitorThread( std::vector<std::pair<ThreadMonitor * , int>> & threads ) : m_threads( threads ) , m_running( false ) {}

MonitorThread::~MonitorThread( ) {
    stop( );
}

void MonitorThread::start( ) {
    m_running = true;
    healthy = false;
    m_thread = std::thread( &MonitorThread::monitorFunction , this );
}

void MonitorThread::stop( ) {
    m_running = false;
    if ( m_thread.joinable( ) ) {
        m_thread.join( );
    }
}

bool MonitorThread::isRunning( ) const {
    return m_running && healthy;
}

void MonitorThread::requestupdate( ) {
    this->healthy = false;
}

void MonitorThread::reset( ) {
    std::cout << crypt_str( "[monitor thread] resetting thread!\n" );
    if ( m_thread.joinable( ) ) {
        m_thread.join( );
    }
    start( );
}

std::string MonitorThread::GetThreadName( int thread ) {
    switch ( thread )
    {
    case DETECTIONS:
        return crypt_str("detections");
    case TRIGGERS:
        return  crypt_str( "triggers");
    case COMMUNICATION:
        return  crypt_str( "communication" );
    }

    return  crypt_str( "undefined" );
}



void MonitorThread::monitorFunction( ) {
    std::cout << crypt_str( "[monitor thread] thread started sucessfully!\n" );
    while ( m_running ) {
        healthy = true;
        std::this_thread::sleep_for( std::chrono::seconds( 30 ) ); // Check every 30 seconds

        std::lock_guard<std::mutex> lock( m_mutex );
        for ( auto & thread : m_threads ) {
            healthy = true;
            if ( !thread.first->isRunning( ) ) {
                std::cout << crypt_str( "[monitor thread][") << GetThreadName(thread.second) << crypt_str("]  Thread is not running properly , resetting...") << std::endl;
                thread.first->reset( );
            }
            else
                thread.first->requestupdate( );
        }
      
    }
}
