#pragma once
#include <string>
#include "../utils/singleton.h"

class Api : public CSingleton<Api>
{
public:
	bool Login( std::string * buffer );
	bool UpdateSessionID( std::string * buffer , std::string SessionID );
};
