#include "ThreadGuard.h"
#include <iostream>

#include "../../Systems/Utils/xorstr.h"
#include "../../client/client.h"
#include "../../Systems/LogSystem/Log.h"
#include "../../Systems/Utils/utils.h"
#include "../../Globals/Globals.h"

ThreadGuard::ThreadGuard( std::vector<std::pair<ThreadHolder * , int>> & threads ) : m_threads( threads ) {}

ThreadGuard::~ThreadGuard( ) {
	stop( );
}



bool ThreadGuard::isRunning( ) const {
	if ( this->ThreadObject->IsThreadSuspended( this->ThreadObject->GetHandle( ) ) ) {
		client::Get( ).SendPunishToServer( xorstr_( "ThreadGuard thread was found suspended, abormal execution" ) , true );
		LogSystem::Get( ).Log( xorstr_( "Failed to run thread" ) );
	}

	if ( !this->ThreadObject->IsThreadRunning( this->ThreadObject->GetHandle( ) ) && !this->ThreadObject->IsShutdownSignalled( ) ) {
		client::Get( ).SendPunishToServer( xorstr_( "ThreadGuard thread was found terminated, abormal execution" ) , true );
		LogSystem::Get( ).Log( xorstr_( "Failed to run thread" ) );
	}

	return true;
}




std::string ThreadGuard::GetThreadName( int thread ) {
	switch ( thread )
	{
	case DETECTIONS:
		return xorstr_( "detections" );
	case TRIGGERS:
		return  xorstr_( "triggers" );
	case COMMUNICATION:
		return  xorstr_( "communication" );
	case ANTIDEBUGGER:
		return xorstr_( "antidebugger" );
	}

	return  xorstr_( "undefined" );
}

HANDLE ThreadGuard::GetThread( int i ) {
	if ( i >= m_threads.size( ) || i < 0 )
		return NULL;

	return m_threads.at( i ).first->ThreadObject->GetHandle( );
}

bool ThreadGuard::IsThreadrunning( int i ) {
	if ( i >= m_threads.size( ) || i < 0 )
		return false;

	return m_threads.at( i ).first->ThreadObject->IsThreadRunning;
}

void ThreadGuard::threadFunction( ) {

	LogSystem::Get( ).ConsoleLog( _MONITOR , xorstr_( "thread started sucessfully, id: " ) + std::to_string( this->ThreadObject->GetId( ) ) , GREEN );

	while ( !Globals::Get( ).VerifiedSession ) {
		//as fast as possible cuh
		std::this_thread::sleep_for( std::chrono::nanoseconds( 1 ) );
	}

	bool Run = true;

	while ( Run ) {
		if ( this->ThreadObject->IsShutdownSignalled( ) ) {
			LogSystem::Get( ).ConsoleLog( _MONITOR , xorstr_( "shutting down thread, shutting down threads" ) , RED );
			for ( auto & thread : this->m_threads ) {
				thread.first->ThreadObject->SignalShutdown( true );
			}
			return;
		}

		if ( this->m_threads.empty( ) ) {
			LogSystem::Get( ).Log( xorstr_( "[301] Can't get threads!\n" ) );
		}

		std::lock_guard<std::mutex> lock( this->m_mutex );
		for ( auto & thread : this->m_threads ) {
			if ( !thread.first->isRunning( ) ) {
				//at this point you will be banned already
			}
		}

		std::this_thread::sleep_for( std::chrono::seconds( this->getThreadSleepTime( ) ) ); // Check every 30 seconds
	}
}
