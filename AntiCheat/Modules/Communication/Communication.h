#pragma once
#include <Windows.h>
#include <string>
#include <thread>
#include <chrono>
#include "../../Client/receiver.h"

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

	void OpenRequestServer( );

	void SendPingToServer( );

	bool InitializeClient( );
	bool SendPasswordToServer( );
	bool CheckReceivedPassword( );

	std::string ExpectedMessage = "";

	std::thread m_thread;
	std::atomic<bool> m_running;
	std::atomic<bool> m_healthy;

	SOCKET openConnection( const char * ipAdress, int port );
	void closeconnection( SOCKET socket );
	SOCKET listenForClient( SOCKET socket , int timeoutSeconds );
	bool sendMessage( SOCKET ClientSocket , std::string message  );
	std::string receiveMessage( SOCKET ClientSocket, int time);



	receiver ServerReceiver;

	SOCKET ListenSocket;
	SOCKET ClientSocket;
public:

	Communication( DWORD Pid , DWORD GamePid  )
		: ProcessPID( Pid ) , GamePID( GamePid ) , m_running( false ) {}

	~Communication( );

	int GetListenerPort( ) { return this->ServerReceiver.GetPort( ); }
	
	void start( );
	void stop( );

	bool isRunning( ) const override;
	void reset( ) override;
	void requestupdate( ) override;
};

