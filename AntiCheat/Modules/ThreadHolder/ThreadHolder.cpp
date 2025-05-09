#include "ThreadHolder.h"

#include "../../Systems/LogSystem/Log.h"

#include "../../Systems/Utils/xorstr.h"

#include <mutex>
#include <vector>

std::vector<bool> threadsReady;
std::mutex threadReadyMutex;

void ThreadHolder::start( ) {
	ThreadObject = std::make_unique<Thread>( ( LPTHREAD_START_ROUTINE ) threadFunctionWrapper , this , true );
	if ( !ThreadObject->GetHandle( ) || ThreadObject->GetHandle( ) == INVALID_HANDLE_VALUE ) {
		LogSystem::Get( ).Error( "Failed to start thread." );
	}
}

void ThreadHolder::reset( ) {
	stop( );
	start( );
}

void ThreadHolder::threadFunctionWrapper( LPVOID instance ) {
	// static_cast< ThreadHolder * >( instance )->waitOtherThreads( );
	static_cast< ThreadHolder * >( instance )->threadFunction( );
}

void ThreadHolder::stop( ) {
	if ( ThreadObject ) {
		ThreadObject->SignalShutdown( true );
	}
}

std::string ThreadHolder::StatusToString( THREAD_STATUS status ) {

	switch ( status ) {
	case THREAD_STATUS::INITIALIZATION_FAILED:
		return xorstr_( "initialization failed" );
	case THREAD_STATUS::NO_STATUS:
		return xorstr_( "no status" );
	case THREAD_STATUS::SUSPENDED:
		return xorstr_( "suspended" );
	case THREAD_STATUS::TERMINATED:
		return xorstr_( "terminated" );
	}

	return xorstr_( "unknown" );
}
std::string ThreadHolder::GetThreadName( THREADS thread ) {
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
	case LISTENER:
		return xorstr_( "listener" );
	case THREADGUARD:
		return xorstr_( "thread guard" );
	}

	return  xorstr_( "undefined" );
}

void ThreadHolder::initializeThreadWaiter( ) {
	while ( threadsReady.size( ) < NO_THREAD - 1 ) {
		threadsReady.emplace_back( false );
	}
}

void ThreadHolder::waitOtherThreads( ) {
	{
		std::lock_guard<std::mutex> lock( threadReadyMutex );
		threadsReady.at( this->getThreaID( ) ) = true;
		LogSystem::Get( ).ConsoleLog( ( MODULE_SENDER ) this->getThreaID( ) , xorstr_( "ready!" ) , WHITE );
	}

	while ( true ) {
		std::vector<bool> localthreadsReady;
		{
			std::lock_guard<std::mutex> lock( threadReadyMutex );
			localthreadsReady = threadsReady;
		}

		bool found = false;

		for ( int i = 0; i < localthreadsReady.size( ); i++ ) {
			if ( !localthreadsReady.at( i ) ) {
				LogSystem::Get( ).ConsoleLog( (MODULE_SENDER)this->getThreaID( ) , xorstr_( "Waiting for " ) + GetThreadName( ( THREADS ) i ) + xorstr_( " thread!" ) , GRAY );
				found = true;
				break;
			}
		}

		if ( !found ) {
			break;
		}
	}
}

THREAD_STATUS ThreadHolder::isRunning( ) {

	if ( this->getThreadStatus( ) != THREAD_STATUS::NO_STATUS ) {
		if ( this->ThreadObject->IsThreadSuspended( this->ThreadObject->GetHandle( ) ) ) {
			return THREAD_STATUS::SUSPENDED;
		}

		if ( !this->ThreadObject->IsThreadRunning( this->ThreadObject->GetHandle( ) ) && !this->ThreadObject->IsShutdownSignalled( ) ) {
			return THREAD_STATUS::TERMINATED;
		}
	}

	return this->getThreadStatus( );
}

