#pragma once

#include <string>


class receiver {

	//std::string key = xorstr_("0123456789abcdef0123456789abcdef"); // 32 bytes para AES-256
	//std::string iv = xorstr_( "abcdef9876543210");  // 16 bytes para AES
	int Port = 54321;

public:
	receiver( );
	~receiver( );

	
	int GetPort( ) { return this->Port; }
	void InitializeConnection( );
};