#pragma once
#include <windows.h>
#include <string>

#include "../Utils/singleton.h"

class Authentication : public CSingleton<Authentication>
{
	BOOL VerifyEmbeddedSignature( std::string pwszSourceFile );
	BOOL VerifyCatalogSignature( std::string filePath );
public:
	BOOL HasSignature( std::string filePath );
};

