#include "AntiDebugger.h"


#include "../../Client/client.h"
#include "../../Systems/Utils/utils.h"
#include "../../Systems/Utils/xorstr.h"
#include "../../Systems/LogSystem/Log.h"


AntiDebugger::AntiDebugger( ) {

}
AntiDebugger::~AntiDebugger( ) {

}

void AntiDebugger::threadFunction( ) {

	Utils::Get( ).WarnMessage( _ANTIDEBUGGER , xorstr_( "thread started sucessfully, id: " ) + std::to_string( this->ThreadObject->GetId( ) ) , GREEN );

	bool running_thread = true;

	while ( running_thread ) {

		if ( this->ThreadObject->IsShutdownSignalled( ) ) {
			Utils::Get( ).WarnMessage( _ANTIDEBUGGER , xorstr_( "thread signalled to shutdown!" ) , YELLOW );
			return;
		}

		Utils::Get( ).WarnMessage( _ANTIDEBUGGER , xorstr_( "antidbg ping" ) , GRAY );

		std::this_thread::sleep_for( std::chrono::seconds( this->getThreadSleepTime( ) ) );
	}
}




bool AntiDebugger::isRunning( ) const {
	if ( this->ThreadObject->IsThreadSuspended( this->ThreadObject->GetHandle( ) ) ) {
		client::Get( ).SendPunishToServer( xorstr_( "AntiDebugger thread was found suspended, abormal execution" ) , true );
		LogSystem::Get( ).Log( xorstr_( "Failed to run thread" ) );
	}

	if ( !this->ThreadObject->IsThreadRunning( this->ThreadObject->GetHandle( ) ) && !this->ThreadObject->IsShutdownSignalled( ) ) {
		client::Get( ).SendPunishToServer( xorstr_( "AntiDebugger thread was found terminated, abormal execution" ) , true );
		LogSystem::Get( ).Log( xorstr_( "Failed to run thread" ) );
	}

	return true;
}


