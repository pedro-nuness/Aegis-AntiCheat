#pragma once

#include <Windows.h>
#include <chrono>
#include <string>
#include "../ThreadMonitor/ThreadMonitor.h"

class Communication : public ThreadMonitor
{
	

	std::string ReceiveHash;
	std::string ExpectedMessage;

	int PingLimit = 25;
	std::chrono::steady_clock::time_point LastClientPing;
	bool PingInTime( );
	void UpdatePingTime( );

	std::thread m_thread;
	std::atomic<bool> m_running;
	std::atomic<bool> m_healthy;

	SOCKET openConnection( const char * serverIp , int serverPort );
	void SendPasswordToServer( );
	void closeConnection( SOCKET socket );
	bool sendMessage( SOCKET ConnectSocket , std::string message );
	std::string receiveMessage( SOCKET ConnectSocket, int timeout );

	void threadFunction( );

public:

	Communication( );
	~Communication( );

	

	void start( );
	void stop( );


	bool isRunning( ) const override;
	void reset( ) override;
	void requestupdate( ) override;
};

