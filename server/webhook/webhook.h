#pragma once
#include <string>
#include "../utils/singleton.h"
#include "../utils/xorstr.h"


class WebHook {
	std::string wHook;

	void * BOT;
	void Start( );
	void BanIp( std::string IP );
	void UnbanIp( std::string IP );
	void * ServerPtr;

	int GetFileUpdateLimit( );

	


public:
	WebHook( );

	void SetServerAddress( void * ptr ) {
		this->ServerPtr = ptr;
	}
	int GuildID = -1;
	int PremiumTier = -1;
	

	bool BotReady = false;
	void * GetServerPTR( ) { return this->ServerPtr; }
	void SendWebHookPunishMent( std::string Message , std::string ScreenshotPath, std::string IP , bool already_banned = false );

	void SendWebHookMessage( std::string Message , std::string TOPIC ,  uint32_t Color = NULL );
	void SendWebHookMessageWithFile( std::string Message, std::string Filename, std::string iP, uint32_t Color = NULL );
	void InitBot( );
};