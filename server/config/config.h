#pragma once
#include <string>
#include "../utils/singleton.h"

class config : public CSingleton<config>
{
	unsigned long long DiscordChannel = 0;
	std::string Username = "";
	std::string ApiKey = "";

	std::string BotToken = "";
	int PingTolerance = 0;
	

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

	int GetPingTolerance( ) {
		return this->PingTolerance;
	}
};

