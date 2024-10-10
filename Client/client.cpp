#include <iostream>
#include <string>
#include <winsock2.h>
#include <iphlpapi.h>

#include "client.h"
#include <intrin.h>
#include <sstream>
#include <fstream>
#include <comdef.h>
#include <Wbemidl.h>

#include "../Systems/Utils/utils.h"
#include "../Systems/Monitoring/Monitoring.h"
#include "../Systems/Hardware/hardware.h"
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")


#include <nlohmann/json.hpp>

using json = nlohmann::json;




client::client( ) {

}
client::~client( ) {

}


bool client::InitializeConnection( ) {
	// Inicializa Winsock

	WSADATA wsaData;
	if ( WSAStartup( MAKEWORD( 2 , 2 ) , &wsaData ) != 0 ) {
		std::cerr << "WSAStartup failed." << std::endl;
		return false;
	}

	// Criar socket e conectar ao servidor
	SOCKET sock = socket( AF_INET , SOCK_STREAM , 0 );
	if ( sock == INVALID_SOCKET ) {
		std::cerr << "Socket creation failed." << std::endl;
		WSACleanup( );
		return false;
	}

	sockaddr_in serverAddr;
	const int serverPort = this->Port;         // Porta que o servidor está escutando

	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons( serverPort );
	serverAddr.sin_addr.s_addr = inet_addr( this->ipaddres.c_str( ) );

	if ( connect( sock , ( sockaddr * ) &serverAddr , sizeof( serverAddr ) ) == SOCKET_ERROR ) {
		std::cerr << "Connection to server failed. Error code: " << WSAGetLastError( ) << std::endl;
		closesocket( sock );
		WSACleanup( );
		return false;
	}

	this->CurrentSocket = sock;

	return true;
}

bool client::CloseConnection( ) {
	if ( this->CurrentSocket != INVALID_SOCKET ) {
		closesocket( this->CurrentSocket );
		WSACleanup( );
		return true;
	}

	return false;
}

bool client::SendData( std::string Data , CommunicationType Type , bool encrypt ) {
	if ( this->CurrentSocket == INVALID_SOCKET )
		return false;

	std::string encryptedMessage;

	if ( encrypt ) {
		if ( !Utils::Get().encryptMessage( Data , encryptedMessage , key , iv ) ) {
			std::cerr << "Failed to encrypt the message." << std::endl;
			return false;
		}
	}
	else
		encryptedMessage = Data;

	encryptedMessage = std::to_string( ( int ) Type ) + encryptedMessage;

	int messageSize = encryptedMessage.size( );
	if ( send( this->CurrentSocket , ( char * ) &messageSize , sizeof( messageSize ) , 0 ) == SOCKET_ERROR ) {
		std::cerr << "Failed to send message size." << std::endl;
		return false;
	}

	// Enviar a mensagem criptografada
	int totalSent = 0;
	while ( totalSent < messageSize ) {
		int sent = send( this->CurrentSocket , encryptedMessage.c_str( ) + totalSent , messageSize - totalSent , 0 );
		if ( sent == SOCKET_ERROR ) {
			std::cerr << "Failed to send encrypted message." << std::endl;
			closesocket( this->CurrentSocket );
			WSACleanup( );
			return false;
		}
		totalSent += sent;
	}

	return true;
}




bool GetHWIDJson( json & js ) {
	std::vector<std::string> MacAddress = hardware::Get().getMacAddress( );
	if ( MacAddress.empty( ) ) {
		return false;
	}

	js[ "mac" ] = MacAddress;

	std::string DiskID = hardware::Get().GetDiskSerialNumber( );

	if ( DiskID.empty( ) )
		return false;

	js[ "disk" ] = DiskID;

	std::string MotherboardID = hardware::Get().GetMotherboardSerialNumber( );

	if ( MotherboardID.empty( ) )
		return false;

	js[ "mb" ] = MotherboardID;

	return true;
}



bool client::SendPingToServer( ) {

	json js;
	if ( !GetHWIDJson( js ) ) {
		std::cout << "Cant get hwid!\n";
		return false;
	}

	std::cout << js.dump( ) << "\n";

	if ( !InitializeConnection( ) ) {
		std::cout << "Failed to initialize connection!\n";
		return false;
	}

	bool sucess = SendData( js.dump( ) , CommunicationType::PING );

	CloseConnection( );

	return sucess;
}

bool client::SendMessageToServer( std::string Message ) {
	if ( Message.empty( ) ) {
		std::cout << "Empty message!\n";
		return false;
	}

	json js;

	if ( !GetHWIDJson( js ) ) {
		std::cout << "Cant get hwid json!\n";
		return false;
	}

	js[ "message" ] = Message;

	if ( !InitializeConnection( ) ) {
		std::cout << "Failed to initialize connection!\n";
		return false;
	}

	bool sucess = SendData( js.dump( ) , CommunicationType::MESSAGE );
	CloseConnection( );

	return sucess;
}

bool client::SendPunishToServer( std::string Message , bool Ban ) {

	json js;

	if ( !GetHWIDJson( js ) ) {
		std::cout << "Cant get hwid json!\n";
		return false;
	}

	if ( Message.empty( ) ) {
		std::cout << "Empty message!\n";
		return false;
	}

	HBITMAP screen = Monitoring::Get().CaptureScreenBitmap( );
	std::vector<BYTE> bitmapData = Monitoring::Get( ).BitmapToByteArray( screen );

	if ( bitmapData.empty( ) ) {
		std::cout << "Can't get screen bitmap!\n";
		return false;
	}

	// Generate hash of the bitmap data
	std::string hash = Utils::Get().GenerateHash( bitmapData );

	if ( hash.empty( ) ) {
		std::cout << "Can't generate hash!\n";
		return false;
	}

	js[ "image" ] = bitmapData;
	js[ "image_hash" ] = hash;
	js[ "message" ] = Message;

	if ( !InitializeConnection( ) ) {
		std::cout << "Failed to initialize connection!\n";
		return false;
	}

	bool sucess = SendData( js.dump( ) , Ban ? CommunicationType::BAN : CommunicationType::WARN , false );
	CloseConnection( );

	return sucess;
}