#pragma once
#include <Windows.h>
#include <string>
#include <ctime>
#include <vector>
#include <mutex>

enum CommunicationType {
	PING ,
	BAN ,
	WARN ,
	MESSAGE ,
	NONE ,
	UNBAN
};

enum CommunicationResponse {
	RECEIVED,
	RECEIVE_ERROR,
	RECEIVE_BANNED
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
	

	void SaveBlockedSets( );
	void LoadBlockedSets( );
	

	bool IsDiskBanned( const std::string & Disk );
	bool IsBiosBanned( const std::string & Bios );
	bool IsMacBanned( const std::vector<std::string> & Macs );
	bool IsSteamBanned( const std::vector<std::string> & Steams );
	std::string AppendHWIDToString( const std::string & str , const std::string & Ip );

	std::vector < Communication > QueuedMessages;
	void handleClient( SOCKET clientSock );
	// Mutex para proteger o acesso a recursos compartilhados

	void ProcessMessages( );

	bool SendData( std::string data, SOCKET socket );



public:
	Server( );
	std::mutex connectionMutex;
	void validateconnections( );
	
	bool UnbanIP( std::string IP );
	bool BanPlayer( const std::string & ip );

	CommunicationResponse receiveping( const std::string & encryptedMessage );
	CommunicationResponse receivemessage( const std::string & encryptedMessage );
	CommunicationResponse receivepunish( const std::string & encryptedMessage , bool ban );

	bool RequestUnbanIp( std::string IP, std::string * buffer );
	bool RequestBanIP( std::string IP, std::string * buffer );
	std::string RequestScreenshotFromClient( std::string Ip );
	std::string GetConnectedPlayers(  );

	void threadfunction( );
};
