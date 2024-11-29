#pragma once

#include <Windows.h>
#include <chrono>
#include <string>
#include <vector>
#include "../ThreadHolder/ThreadHolder.h"

class Communication : public ThreadHolder
{
	std::string ReceiveHash;
	std::string ExpectedMessage;

	std::vector<std::string> QueuedMessages;

	int PingLimit = 25;
	std::chrono::steady_clock::time_point LastClientPing;
	bool PingInTime( );
	void UpdatePingTime( );


	SOCKET openConnection( const char * serverIp , int serverPort );
	void SendPasswordToServer( );
	void closeConnection( SOCKET socket );
	bool sendMessage( SOCKET ConnectSocket , std::string message );
	std::string receiveMessage( SOCKET ConnectSocket, int timeout );

	void threadFunction( ) override;

public:

	Communication( );
	~Communication( );

	void AddMessageToQueue( std::string );

	


	bool isRunning( ) const override;
};

