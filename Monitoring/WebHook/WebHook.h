#pragma once
#include <string>
class WebHook {
	std::string wHook;


public:
	WebHook(std::string  _wHook) {
		this->wHook = _wHook;
	}

	void SendWebHookMessage( std::string Message, uint32_t Color = NULL );
	void SendWebHookMessageWithFile( std::string Message, std::string Filename, uint32_t Color = NULL );
};