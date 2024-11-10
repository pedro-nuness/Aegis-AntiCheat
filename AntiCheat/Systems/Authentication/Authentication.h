#pragma once
#include <windows.h>
#include <string>

#include "../Utils/singleton.h"

class Authentication : public CSingleton<Authentication>
{
public:
	BOOL VerifyEmbeddedSignature( std::string pwszSourceFile );
	BOOL VerifyCatalogSignature( std::string filePath );
	BOOL HasSignature( std::string filePath );
};

