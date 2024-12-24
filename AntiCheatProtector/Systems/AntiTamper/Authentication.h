#pragma once
#include <windows.h>
#include <string>

#include "../Utils/singleton.h"

enum AUTHENTICATION_RESPONSE {
	FAILED_TO_GET ,
	NOT_AUTHENTICATED ,
	AUTHENTICATED,
	NONE_AUTHENTICATION
};

class Authentication : public CSingleton<Authentication>
{
	AUTHENTICATION_RESPONSE VerifyEmbeddedSignature( std::string pwszSourceFile );
	AUTHENTICATION_RESPONSE VerifyCatalogSignature( std::string filePath );
public:
	BOOL HasSignature( std::string filePath );
};

