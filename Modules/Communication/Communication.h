#pragma once
#include <Windows.h>
#include <string>
#include <thread>
#include "../ThreadMonitor/ThreadMonitor.h"


class Communication : public ThreadMonitor {

	std::string ProcessName; 
	DWORD ProcessPID; 
	DWORD GamePID; 
	std::string AuthenticMemoryHash;
	std::string ProcessMemoryHash;

	std::string CommunicationHash;


	void threadFunction( );

	std::thread m_thread;
	std::atomic<bool> m_running;
	std::atomic<bool> m_healthy;

	SOCKET openconnection( );
	void closeconnection( SOCKET socket );
	SOCKET listenForClient( SOCKET socket , int timeoutSeconds );
	void sendMessage( SOCKET ClientSocket , const char * message );
	std::string receiveMessage( SOCKET ClientSocket );

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

