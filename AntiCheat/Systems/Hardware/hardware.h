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
	std::string GetIp(  );
	bool GetLoggedUsers( std::vector<std::string> * Buffer);

	void GenerateCache( );
};

