#pragma once
#include <Windows.h>
#include <string>
#include "../Systems/Utils/xorstr.h"
#include "../Systems/Utils/singleton.h"




enum CommunicationResponse {
	RECEIVED ,
	RECEIVE_ERROR ,
	RECEIVE_BANNED ,
	RECEIVE_INVALIDSESSION ,
	RECEIVE_LOGGEDIN ,
	RECEIVE_NOT_LOGGEDIN ,
	RECEIVED_SCREENSHOTREQUEST ,
	RECEIVED_WRONGAUTH,
	NORESPONSE
};


enum CommunicationType {
	PING ,
	BAN ,
	WARN ,
	MESSAGE ,
	SCREENSHOT ,
	UNBAN ,
	LOGIN ,
	NONE
};

enum SuccessStatus {
	NOTHING ,
	TRYAGAIN ,
	DENIED ,
	SUCCESS ,
	CANT_CONNECT
};

class Response {
	std::string SessionID;
	CommunicationResponse SvResponse;

public:
	Response( CommunicationResponse cr , std::string str ) {
		this->SessionID = str;
		this->SvResponse = cr;
	}

	CommunicationResponse GetServerResponse( ) { return this->SvResponse; }
	bool ReceivedSessionID( ) { return !this->SessionID.empty( ); }
	std::string GetSessionID( ) { return this->SessionID; }
};

class client {

	//std::string key = xorstr_("ib33o5m8zsqlcgys3w46cfmtn8ztg1kn"); // 32 bytes para AES-256
	//std::string iv = xorstr_( "ume9ugz3m7lgch1z");  // 16 bytes para AES
	std::string ipaddres = xorstr_( "172.84.94.156" );
	int Port = 2452;

	std::string IV;
	std::string SessionID;

	SOCKET CurrentSocket;
	bool InitializeConnection( );
	bool ReceiveInformation( std::string * buffer );
	bool GetResponse( Response * resp_buff );
	bool CloseConnection( );
	bool SendData( std::string Data , CommunicationType Type , bool encrypt = true );
	bool SendDataToServer( std::string js , CommunicationType type, Response * res_ptr );
public:
	client( );
	~client( );


	std::string GetIV( ) { return this->IV; }
	std::string GetSessionID( ) { return this->SessionID; }

	void SetIV( std::string IV_ ) { this->IV = IV_; }
	void SetSessionID( std::string ID ) { this->SessionID = ID; }


	bool LoginToServer( );
	bool SendMessageToServer( std::string Message );
	bool SendPingToServer( );
	bool SendPunishToServer( std::string Message , CommunicationType Type );
};

extern client _client;