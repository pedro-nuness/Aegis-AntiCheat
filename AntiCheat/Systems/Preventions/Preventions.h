#pragma once
#include "../Utils/singleton.h"


class Preventions : public CSingleton<Preventions>
{



public:

	bool EnableApiHooks( bool Log = false);
	bool RestrictProcessAccess( );
	bool RandomizeModuleName( );
	bool RemapProgramSections( );
	bool EnableProcessMitigations( bool useDEP , bool useASLR , bool useDynamicCode , bool useStrictHandles , bool useSystemCallDisable );
	bool PreventDllInjection( );
	bool PreventThreadCreation( );
	bool StopAPCInjection( );
	bool DeployDllLoadNotifation( );

	bool DeployFirstBarrier( );
	bool DeployMidBarrier( );
	bool DeployLastBarrier( );
};

