#pragma once

#include <unordered_set>
#include <string>
#include <unordered_map>
#include <ctime>

#include "../utils/singleton.h"
#include "../webhook/webhook.h"



#define default_encrypt_salt "FMJ892FJfni8HNGFJADO432190GFSAMG"
#define server_key xorstr_("ib33o5m8zsqlcgys3w46cfmtn8ztg1kn") // 32 bytes para AES-256
#define server_iv xorstr_("ume9ugz3m7lgch1z") // 16 bytes para AES

class Connection {
	std::vector<std::string> MAC;
	std::string Motherboard;
	std::string DiskID;
	std::string Ip;
	std::string Nickname;
	std::vector<std::string> SteamID;
	std::time_t LastPing;
	std::string LastIV;
	std::string SessionID;
	

	void InitializeSession( );



public:
	Connection( ) {
		this->LastPing = std::time( 0 );
		this->MAC = { "" };
		this->Motherboard = "";
		this->DiskID = "";
		this->Ip = "";
		InitializeSession( );
	}

	Connection( std::string Nick , std::vector<std::string> Steam , std::vector<std::string> MAC , std::string Mb , std::string Disk , std::string _Ip , std::time_t Ping ) {
		this->Nickname = Nick;
		this->SteamID = Steam;
		this->MAC = MAC;
		this->Motherboard = Mb;
		this->DiskID = Disk;
		this->LastPing = std::time( 0 );
		this->Ip = _Ip;
		InitializeSession( );
	}

	bool WhiteListed = false;

	void UpdateIVCode( );

	std::string GetIp( ) { return this->Ip; }
	std::string GetLastIV( ) { return this->LastIV; }
	std::string GetSessionID( ) { return this->SessionID; }
	std::vector<std::string> GetMac( ) { return this->MAC; }
	std::string GetMotherboard( ) { return this->Motherboard; }
	std::string GetDiskID( ) { return this->DiskID; }
	std::string GetNickname( ) { return this->Nickname; }
	std::vector<std::string> GetSteamID( ) { return this->SteamID; }

	void Ping( ) { this->LastPing = std::time( 0 ); }
	int GetLastPing( ) { return (int)(std::difftime( std::time( 0 ) , LastPing )); }
	
};


class globals
{
public:
	std::unordered_map<std::string , Connection> ConnectionMap;
	std::unordered_map<std::string, Connection> BannedPlayers;
	std::vector<std::string> WhiteListedIps;

	std::unordered_set<std::string> blockedBIOS;
	std::unordered_set<std::string> blockedDisks;
	std::unordered_set<std::string> blockedMacs;
	std::unordered_set<std::string> blockedSteamID;
	std::unordered_set<std::string> RequestedScreenshot;

	bool ServerOpen = false;
	bool AcessingMap = false;
	bool ValidatingConnections = false;
	bool LoggedIn = false;
	bool LockConnections = true;
	bool NoAuthentication = false;
	bool Usebot = true;
	std::string SelfIP;
	std::string VerifiedSessionID;
	std::string CurrentPath;
	WebHook whook;

};
extern globals _globals;
