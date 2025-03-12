#pragma once
#include <Windows.h>
#include <string>
#include <ctime>
#include <vector>
#include <mutex>
#include <unordered_map>


enum CommunicationType {
	PING ,
	BAN ,
	WARN ,
	MESSAGE ,
	SCREENSHOT,
	UNBAN,
	LOGIN,
	NONE
};

class Connection;


enum WHOOKTYPE {
	NOTHING ,
	MESSAGE_ ,
	MESSAGE_FILE ,
	BAN_ ,
	WARN_ ,
};

struct WHookRequest {

	WHOOKTYPE Type = WHOOKTYPE::NOTHING;
	std::string Message = "undefined message";
	std::string Filename = "undefined";
	std::string Ip = "undefined";
	uint32_t Color = 0;

public:

	WHookRequest( WHOOKTYPE type , std::string m , std::string f , std::string ip , uint32_t c ) {
		this->Type = type;
		this->Message = m;
		this->Filename = f;
		this->Color = c;
		this->Ip = ip;
	}

	[[nodiscard]] std::string GetMessage_( ) const { return Message; }
	[[nodiscard]] std::string GetFilename_( ) const { return Filename; }
	[[nodiscard]] uint32_t GetColor_( ) const { return Color; }
	[[nodiscard]] std::string GetIP( ) const { return Ip; }
	[[nodiscard]] WHOOKTYPE GetType( ) const { return Type; }
};



enum CommunicationResponse {
	RECEIVED ,
	RECEIVE_ERROR ,
	RECEIVE_BANNED ,
	RECEIVE_INVALIDSESSION ,
	RECEIVE_LOGGEDIN ,
	RECEIVE_NOT_LOGGEDIN ,
	RECEIVED_SCREENSHOTREQUEST ,
	RECEIVED_WRONGAUTH
};


struct Communication {
	Communication( CommunicationType MT, std::string M, SOCKET S) {
		this->MessageType = MT;
		this->Message = M;
		this->Socket = S;
	}

	CommunicationType MessageType;
	std::string Message;
	SOCKET Socket;
};


class Server {
	

	void SaveConnectionSet( std::unordered_map<std::string , Connection> * Set, std::string filename );
	void LoadConnectionSet( std::unordered_map<std::string , Connection> & Set, std::string filename );
	void LoadBlockedSet( );
	

	bool IsDiskBanned( const std::string & Disk );
	bool IsBiosBanned( const std::string & Bios );
	bool IsMacBanned( const std::vector<std::string> & Macs );
	bool IsSteamBanned( const std::vector<std::string> & Steams );

	void CacheConnections( );


	std::string AppendHWIDToString( const std::string & str , const std::string & Ip );

	std::vector < Communication > QueuedMessages;
	void handleClient( SOCKET clientSock );
	// Mutex para proteger o acesso a recursos compartilhados

	void ProcessMessages( );

	bool SendData( std::string data, SOCKET socket );

	std::vector<WHookRequest> WebhookList;

	void ProcessWebHookRequests( );



public:
	Server( );
	std::mutex connectionMutex;
	std::mutex ScreenshotMutex;
	void validateconnections( );
	
	bool UnbanIP( std::string IP );
	bool BanPlayer( const std::string & ip );
	
	CommunicationResponse receivelogin( const std::string & encryptedMessage );
	CommunicationResponse receiveping( const std::string & encryptedMessage, std::string * Ip );
	CommunicationResponse receivemessage( const std::string & encryptedMessage );
	CommunicationResponse receivepunish( const std::string & encryptedMessage , CommunicationType type );

	bool RequestUnbanIp( std::string IP, std::string * buffer );
	bool RequestBanIP( std::string IP, std::string * buffer );
	std::string RequestScreenshotFromClient( std::string Ip );
	std::string GetConnectedPlayers(  );

	void threadfunction( );
};
