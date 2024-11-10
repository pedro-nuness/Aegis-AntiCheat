#pragma once
#include "../../Process/Thread.hpp"
#include "../ThreadHolder/ThreadHolder.h"

class AntiDebugger : public ThreadHolder
{

	void threadFunction( ) override;
public:
	AntiDebugger( );
	~AntiDebugger( );


	bool isRunning( ) const override;
};

