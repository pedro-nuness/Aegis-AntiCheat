#include "MonitorThread.h"
#include <iostream>

#include "../../Systems/Utils/xorstr.h"
#include "../../Systems/LogSystem/Log.h"
#include "../../Systems/Utils/utils.h"

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
    Utils::Get( ).WarnMessage( DARK_BLUE , xorstr_( "monitor thread" ) , xorstr_( "resetting thread" ) , YELLOW );
    if ( m_thread.joinable( ) ) {
        m_thread.join( );
    }
    start( );
}

std::string MonitorThread::GetThreadName( int thread ) {
    switch ( thread )
    {
    case DETECTIONS:
        return xorstr_( "detections" );
    case TRIGGERS:
        return  xorstr_( "triggers" );
    case COMMUNICATION:
        return  xorstr_( "communication" );
    }

    return  xorstr_( "undefined" );
}



void MonitorThread::monitorFunction( ) {
    Utils::Get( ).WarnMessage( DARK_BLUE , xorstr_( "monitor thread" ) , xorstr_( "thread started sucessfully" ) , GREEN );
    while ( m_running ) {
        healthy = true;
        std::this_thread::sleep_for( std::chrono::seconds( 30 ) ); // Check every 30 seconds

        if ( m_threads.empty( ) ) {
            LogSystem::Get( ).Log( xorstr_( "[301] Can't get threads!\n" ) );
        }

        std::lock_guard<std::mutex> lock( m_mutex );
        for ( auto & thread : m_threads ) {
            healthy = true;
            if ( !thread.first->isRunning( ) ) {
                Utils::Get( ).WarnMessage( DARK_BLUE , xorstr_( "monitor thread" ) , GetThreadName( thread.second ) + xorstr_( " is not running properly , resetting... " ) , RED );
                thread.first->reset( );
            }
            else
                thread.first->requestupdate( );
        }

    }
}
