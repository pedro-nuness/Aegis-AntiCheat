#pragma once
#include <Windows.h>
#include <string>
#include <thread>
#include <chrono>

#include "../../Process/Thread.hpp"
#include "../ThreadHolder/ThreadHolder.h"

class Communication : public ThreadHolder {

	std::string ProcessName; 
	DWORD ProcessPID; 
	DWORD GamePID; 
	std::string AuthenticMemoryHash;
	std::string ProcessMemoryHash;

	std::string CommunicationHash;

	bool ShutdownServerPing = false;

	void SignalShutdown( bool shut ) { this->ShutdownServerPing = shut; }
	bool IsShutdownSignalled( ) { return this->ShutdownServerPing; }

	int PingLimit = 15;
	std::chrono::steady_clock::time_point LastClientPing;
	bool PingInTime( );
	void UpdatePingTime( );
	void HandleMissingPing( );

	void threadFunction( ) override;

	bool ReceivedQueuedMessage(std::string );

	void OpenRequestServer( );

	static void SendPingToServer( LPVOID AD);


	bool SendPasswordToServer( );
	bool CheckReceivedPassword( );

	std::string ExpectedMessage = "";

	SOCKET openConnection( const char * ipAdress, int port );
	void closeconnection( SOCKET socket );
	SOCKET listenForClient( SOCKET socket , int timeoutSeconds );
	bool sendMessage( SOCKET ClientSocket , std::string message  );
	std::string receiveMessage( SOCKET ClientSocket, int time);


	int ServerResponse = -1;

	SOCKET ListenSocket;
	SOCKET ClientSocket;
public:

	static bool InitializeClient( );

	Communication( DWORD Pid , DWORD GamePid  )
		: ProcessPID( Pid ) , GamePID( GamePid )  {}

	~Communication( );

	bool isRunning( ) const override;
};

