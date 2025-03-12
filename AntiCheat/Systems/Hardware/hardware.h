#pragma once
#include <vector>
#include <string>
#include "../Utils/singleton.h"

class hardware : public CSingleton<hardware>
{

public:
	bool GetMotherboardSerialNumber( std::string * buffer);
	bool GetDiskSerialNumber( std::string * buffer );
	std::vector<std::string> getMacAddress( );
	bool GetIp( std::string * buffer );
	bool GetLoggedUsers( std::vector<std::string> * Buffer);
	bool GetUniqueUID( std::string * buffer, std::string ID = "" );
	bool GetVersionUID( std::string * buffer );

	bool GenerateInitialCache( );
	bool EndCacheGeneration( );

};

