#pragma once

// Inclui bibliotecas do Windows e cabe�alho do Singleton
#include <windows.h>
#include "../utils/singleton.h"
#include <string>

// Classe sender, utilizando o padr�o Singleton
class sender
{
    SOCKET CurrentSocket = INVALID_SOCKET;
    std::string IpAddress;
    int port = 54321;

    bool InitializeConnection( );
    bool CloseConnection( );
    bool SendData( std::string data );


public:
    // Construtor da classe sender
    sender( std::string ip ) : IpAddress( ip ) {}

    // M�todo para enviar mensagem ao servidor
    bool SendMessageToServer( std::string Message );
};
