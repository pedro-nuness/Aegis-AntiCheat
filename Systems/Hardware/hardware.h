#pragma once
#include <vector>
#include <string>
#include "../Utils/singleton.h"

class hardware : public CSingleton<hardware>
{
public:
	std::string GetMotherboardSerialNumber( );
	std::string GetDiskSerialNumber( );
	std::vector<std::string> getMacAddress( );
	std::string GetIp( int port );
};

