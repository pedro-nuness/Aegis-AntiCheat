#pragma once

#include <unordered_set>
#include <string>
#include <unordered_map>
#include <ctime>

#include "../utils/singleton.h"
#include "../webhook/webhook.h"



class Connection {
	std::vector<std::string> MAC;
	std::string Motherboard;
	std::string DiskID;
	std::string Ip;
	std::string Nickname;
	std::vector<std::string> SteamID;
	std::time_t LastPing;
public:
	Connection( ) {
		this->LastPing = std::time( 0 );
		this->MAC = { "" };
		this->Motherboard = "";
		this->DiskID = "";
		this->Ip = "";
	} 

	Connection( std::string Nick, std::vector<std::string> Steam, std::vector<std::string> MAC , std::string Mb , std::string Disk , std::string _Ip , std::time_t Ping ) {
		this->Nickname = Nick;
		this->SteamID = Steam;
		this->MAC = MAC;
		this->Motherboard = Mb;
		this->DiskID = Disk;
		this->LastPing = std::time( 0 );
		this->Ip = _Ip;
	}
	std::string GetIp( ) { return this->Ip; }
	std::vector<std::string> GetMac( ) { return this->MAC; }
	std::string GetMotherboard( ) { return this->Motherboard; }
	std::string GetDiskID( ) { return this->DiskID; }
	std::string GetNickname( ) { return this->Nickname; }
	std::vector<std::string> GetSteamID( ) { return this->SteamID; }

	void Ping( ) { this->LastPing = std::time( 0 ); }
	int GetLastPing( ) { return (int)(std::difftime( std::time( 0 ) , LastPing )); }
	
};


class globals : public CSingleton<globals>
{
public:
	std::unordered_map<std::string , Connection> ConnectionMap;
	std::unordered_map<std::string, Connection> BannedPlayers;

	std::unordered_set<std::string> blockedBIOS;
	std::unordered_set<std::string> blockedDisks;
	std::unordered_set<std::string> blockedMacs;
	std::unordered_set<std::string> blockedSteamID;

	bool ServerOpen = false;
	bool AcessingMap = false;
	bool ValidatingConnections = false;
	bool LoggedIn = false;
	bool LockConnections = true;
	bool Usebot = true;
	std::string SelfIP;
	WebHook whook;

};

