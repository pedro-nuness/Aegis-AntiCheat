#pragma once
#include <Windows.h>
#include <string>
#include <thread>
#include <chrono>

#include "../ThreadMonitor/ThreadMonitor.h"


class Communication : public ThreadMonitor {

	std::string ProcessName; 
	DWORD ProcessPID; 
	DWORD GamePID; 
	std::string AuthenticMemoryHash;
	std::string ProcessMemoryHash;

	std::string CommunicationHash;

	int PingLimit = 25;
	std::chrono::steady_clock::time_point LastClientPing;
	bool PingInTime( );
	void UpdatePingTime( );
	void HandleMissingPing( );

	void threadFunction( );

	std::thread m_thread;
	std::atomic<bool> m_running;
	std::atomic<bool> m_healthy;

	SOCKET openConnection( const char * ipAdress );
	void closeconnection( SOCKET socket );
	SOCKET listenForClient( SOCKET socket , int timeoutSeconds );
	void sendMessage( SOCKET ClientSocket , const char * message );
	std::string receiveMessage( SOCKET ClientSocket, int time);

	SOCKET ListenSocket;
	SOCKET ClientSocket;
public:

	Communication( DWORD Pid , DWORD GamePid  )
		: ProcessPID( Pid ) , GamePID( GamePid ) , m_running( false ) {}

	~Communication( );
	
	void start( );
	void stop( );

	bool isRunning( ) const override;
	void reset( ) override;
	void requestupdate( ) override;
};

