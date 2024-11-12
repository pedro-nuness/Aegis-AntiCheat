#include "ThreadHolder.h"

#include "../../Systems/LogSystem/Log.h"

void ThreadHolder::start( ) {
	ThreadObject = std::make_unique<Thread>( ( LPTHREAD_START_ROUTINE ) threadFunctionWrapper , this , true );
	if ( !ThreadObject->GetHandle( ) || ThreadObject->GetHandle( ) == INVALID_HANDLE_VALUE ) {
		LogSystem::Get( ).Log( "Failed to start thread." );
	}
}

void ThreadHolder::reset( ) {
	stop( );
	start( );
}

void ThreadHolder::threadFunctionWrapper( LPVOID instance ) {
	static_cast< ThreadHolder * >( instance )->threadFunction( );
}

void ThreadHolder::stop( ) {
	if ( ThreadObject ) {
		ThreadObject->SignalShutdown( true );
		WaitForSingleObject( ThreadObject->GetHandle( ) , INFINITE );
	}
}