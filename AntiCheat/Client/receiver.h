#pragma once

#include <string>


class receiver {

	//std::string key = xorstr_("ib33o5m8zsqlcgys3w46cfmtn8ztg1kn"); // 32 bytes para AES-256
	//std::string iv = xorstr_( "ume9ugz3m7lgch1z");  // 16 bytes para AES
	int Port = 54321;

public:
	receiver( );
	~receiver( );

	void ProcessJson( std::string Json );
	int GetPort( ) { return this->Port; }
	void InitializeConnection( );
};