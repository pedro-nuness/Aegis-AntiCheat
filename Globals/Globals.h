#pragma once
#include <string>

#include "../Utils/singleton.h"
#include "../Utils/crypt_str.h"


class Globals : public CSingleton<Globals>
{
public:
	int OriginalProcess;
	int ProtectProcess;
};

