#pragma once

#include <Windows.h>
#include "../ThreadHolder/ThreadHolder.h"
#include <mutex>
#include <string>


class Listener : public ThreadHolder {



	void handleClient( SOCKET clientSock );
	void ProcessMessages( );

	void threadFunction( ) override;

	void GenerateRandomPort( );
	int port = -1;

	bool savePort( std::string port );
	std::string readPort( );

public:

	int GetPort( ) {
		return this->port;
	}

	Listener( );
	~Listener( );
};

