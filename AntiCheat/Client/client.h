#pragma once
#include <Windows.h>
#include <string>
#include "../Systems/Utils/xorstr.h"
#include "../Systems/Utils/singleton.h"



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
	//std::string iv = xorstr_( "ume9ugz3m7lgch1z");  // 16 bytes para AES
	std::string ipaddres = xorstr_( "26.114.178.232");
	int Port = 12345;


	SOCKET CurrentSocket;
	bool InitializeConnection( );
	bool GetResponse( CommunicationResponse * response );
	bool CloseConnection( );
	bool SendData( std::string Data , CommunicationType Type , bool encrypt = true );
public:
	client( );
	~client( );



	bool SendMessageToServer( std::string Message );
	bool SendPingToServer( );
	bool SendPunishToServer( std::string Message , bool BAN);
};