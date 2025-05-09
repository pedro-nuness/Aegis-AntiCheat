#pragma once

#include <Windows.h>
#include "../ThreadHolder/ThreadHolder.h"


#include <mutex>


class Listener : public ThreadHolder {

	void handleClient( SOCKET clientSock );
	void ProcessMessages( );

	void threadFunction( ) override;
public:

	Listener( );
	~Listener( );
};

