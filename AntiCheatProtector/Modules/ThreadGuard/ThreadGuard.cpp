#include "ThreadGuard.h"
#include <iostream>

#include "../../Systems/Utils/xorstr.h"
#include "../../Systems/LogSystem/Log.h"
#include "../../Systems/Utils/utils.h"
#include "../../Globals/Globals.h"
#include "../../Client/client.h"

std::mutex ListMutex;

ThreadGuard::ThreadGuard( std::vector<std::pair<ThreadHolder * , int>> & threads ) {
	this->m_threads = threads;
	for ( auto thread : m_threads ) {
		this->RunningThreadsID.emplace_back( thread.first->ThreadObject->GetId( ) );
	}
}

ThreadGuard::~ThreadGuard( ) {
	stop( );
}

void ThreadGuard::AddThreadToList( DWORD PID ) {
	std::lock_guard<std::mutex> lock( ListMutex );
	this->RunningThreadsID.emplace_back( PID );
}

std::vector<DWORD> ThreadGuard::GetRunningThreadsID( ) {
	return this->RunningThreadsID;
}

std::vector<HANDLE> ThreadGuard::GetRunningThreadHandle( ) {
	std::vector<HANDLE> Result;
	
	for ( auto & thread : this->m_threads ) {
		Result.emplace_back( thread.first->ThreadObject->GetHandle( ) );
	}
	return Result;
}


bool ThreadGuard::isRunning( ) const {
	if ( this->ThreadObject->IsThreadSuspended( this->ThreadObject->GetHandle( ) ) ) {	
		
		client newclient;
		newclient.SendMessageToServer( xorstr_( "ThreadGuard suspended!" ) , BAN );
		

		LogSystem::Get( ).Log( xorstr_( "Failed to run thread" ) );
		return false;
	}

	if ( !this->ThreadObject->IsThreadRunning( this->ThreadObject->GetHandle( ) ) && !this->ThreadObject->IsShutdownSignalled( ) ) {
	
		client newclient;
		newclient.SendMessageToServer( xorstr_( "ThreadGuard Terminated!" ) , BAN );

		LogSystem::Get( ).Log( xorstr_( "Failed to run thread" ) );
		return false;
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


void ThreadGuard::threadFunction( ) {

	LogSystem::Get( ).ConsoleLog( _MONITOR , xorstr_( "thread started sucessfully, id: " ) + std::to_string( this->ThreadObject->GetId( ) ) , GREEN );

	while ( !Globals::Get( ).VerifiedSession ) {
		if ( this->ThreadObject->IsShutdownSignalled( ) ) {
			LogSystem::Get( ).ConsoleLog( _MONITOR , xorstr_( "shutting down thread, shutting down threads" ) , RED );
			for ( auto & thread : this->m_threads ) {
				thread.first->ThreadObject->SignalShutdown( true );
			}
			return;
		}

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
