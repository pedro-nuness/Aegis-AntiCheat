#pragma once
#include <Windows.h>

#include "../Systems/Utils/singleton.h"


enum CommunicationType {
	PING ,
	BAN ,
	WARN ,
	MESSAGE
};

class client : public CSingleton<client>{
	std::string key = "0123456789abcdef0123456789abcdef"; // 32 bytes para AES-256
	std::string iv = "abcdef9876543210";  // 16 bytes para AES
	std::string ipaddres = "26.239.241.101";
	int Port = 12345;

	SOCKET CurrentSocket;
	bool InitializeConnection( );
	bool CloseConnection( );
	bool SendData( std::string Data , CommunicationType Type , bool encrypt = true );
public:
	client( );
	~client( );

	bool SendMessageToServer( std::string Message );
	bool SendPingToServer( );
	bool SendPunishToServer( std::string Message , bool BAN );
};

