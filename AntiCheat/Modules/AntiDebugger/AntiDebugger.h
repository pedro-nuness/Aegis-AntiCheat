#pragma once
#include "../../Process/Thread.hpp"
#include "../ThreadHolder/ThreadHolder.h"

class AntiDebugger : public ThreadHolder
{
    bool _IsDebuggerPresent( ) { return IsDebuggerPresent( ); }
    bool _IsDebuggerPresent_HeapFlags( );
    bool _IsDebuggerPresent_CloseHandle( );
    bool _IsDebuggerPresent_RemoteDebugger( );
    bool _IsDebuggerPresent_VEH( );
    bool _IsDebuggerPresent_DbgBreak( );
    bool _IsDebuggerPresent_PEB( );
    bool _IsDebuggerPresent_DebugPort( );
    bool _IsDebuggerPresent_ProcessDebugFlags( );
    bool _IsKernelDebuggerPresent( );
    bool _IsKernelDebuggerPresent_SharedKData( );

	void threadFunction( ) override;
public:
	AntiDebugger( );
	~AntiDebugger( );

};

