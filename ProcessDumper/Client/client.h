#pragma once
#include <Windows.h>
#include <string>
#include "../utils/xorstr.hpp"
#include "../utils/singleton.h"



enum CommunicationResponse {
	RECEIVED ,
	RECEIVE_ERROR ,
	RECEIVE_BANNED
};


enum CommunicationType {
	PING ,
	BAN ,
	WARN ,
	MESSAGE
};

class client : public CSingleton<client>{

	//std::string key = xorstr_("ib33o5m8zsqlcgys3w46cfmtn8ztg1kn"); // 32 bytes para AES-256
	std::string iv = xorstr_( "vbDRxXb3ObIZeVSN");  // 16 bytes para AES
	std::string ipaddres = xorstr_( "127.0.0.10");
	int Port = 9669;

	SOCKET CurrentSocket;
	bool InitializeConnection( );
	bool GetResponse( CommunicationResponse * response );
	bool CloseConnection( );
	bool SendData( std::string Data , CommunicationType Type , bool encrypt = true );
public:
	client( );
	~client( );

	bool SendMessageToServer( std::string Message, CommunicationType );
};