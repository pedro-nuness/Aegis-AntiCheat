#include "ThreadGuard.h"
#include <iostream>

#include "../../Systems/Utils/xorstr.h"
#include "../../client/client.h"
#include "../../Systems/LogSystem/Log.h"
#include "../../Systems/Utils/utils.h"
#include "../../Globals/Globals.h"

std::mutex ListMutex;

ThreadGuard::ThreadGuard( std::vector<std::pair<ThreadHolder * , int>> & threads ) 
	: ThreadHolder( THREADS::THREADGUARD )
{
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





void ThreadGuard::threadFunction( ) {

	LogSystem::Get( ).ConsoleLog( _MONITOR , xorstr_( "thread started sucessfully, id: " ) + std::to_string( this->ThreadObject->GetId( ) ) , GREEN );

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
			LogSystem::Get( ).Error( xorstr_( "[301] Can't get threads!\n" ) );
		}

		std::lock_guard<std::mutex> lock( this->m_mutex );
		for ( auto & thread : this->m_threads ) {

			std::string threadName = ThreadHolder::GetThreadName( thread.first->getThreaID( ) );
			THREAD_STATUS status = thread.first->isRunning( );
			std::string StatusString = ThreadHolder::StatusToString( status );

			LogSystem::Get( ).ConsoleLog( _MONITOR , threadName + xorstr_( " status: " ) + StatusString , WHITE );

			switch ( status ) {
			case THREAD_STATUS::INITIALIZATION_FAILED:
					LogSystem::Get( ).ConsoleLog( _MONITOR , threadName + xorstr_( " thread initialization failed!" ) , RED );
					this->ThreadObject->SignalShutdown( true );
				break;
			case THREAD_STATUS::TERMINATED:
				_client.SendPunishToServer( threadName + xorstr_( " thread was found terminated! Abnormal execution" ) , CommunicationType::BAN );
				break;

			case THREAD_STATUS::SUSPENDED:
				_client.SendPunishToServer( threadName + xorstr_( " thread was found suspended! Abnormal execution" ) , CommunicationType::BAN );
				break;
			}
		}

		std::this_thread::sleep_for( std::chrono::seconds( this->getThreadSleepTime( ) ) ); // Check every 30 seconds
	}
}
