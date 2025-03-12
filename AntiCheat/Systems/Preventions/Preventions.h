#pragma once
#include "../Utils/singleton.h"

class Preventions : public CSingleton<Preventions>
{
	bool EnableApiHooks( );
	bool RestrictProcessAccess( );
	bool RandomizeModuleName( );
	bool RemapProgramSections( );
	bool EnableProcessMitigations( bool useDEP , bool useASLR , bool useDynamicCode , bool useStrictHandles , bool useSystemCallDisable );
	bool PreventDllInjection( );
	bool PreventThreadCreation( );
	bool StopAPCInjection( );
	bool DeployDllLoadNotifation( );
public:
	int Deploy( );
};

