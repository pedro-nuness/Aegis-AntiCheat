#pragma once
#include <string>
#include <unordered_set>
#include "../utils/singleton.h"

class config 
{
	unsigned long long DiscordChannel = 0;
	std::string Username = "";
	std::string ApiKey = "";

	std::string BotToken = "";
	int PingTolerance = 0;
	int CapturePort = 0;

	std::unordered_set<std::string> WhitelistedIps;
	
	void LoadWhiteListedPlayers( );

public:
	void LoadConfig( );


	unsigned long long GetDiscordChannel( ) {
		return this->DiscordChannel;
	}

	std::string GetUsername( ) { return this->Username; }

	std::string GetApiKey( ) {
		return this->ApiKey;
	};

	std::string GetBotToken( ) {
		return this->BotToken;
	}

	int GetCapturePort( ) { return this->CapturePort; }

	const std::unordered_set<std::string> & GetWhiteListedPlayers( ) const {
		return this->WhitelistedIps;
	}


	int GetPingTolerance( ) {
		return this->PingTolerance;
	}
};

extern config _config;
