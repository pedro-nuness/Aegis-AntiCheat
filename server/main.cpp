#include <iostream>
#include <windows.h>
#include "windivert.h"
#include <vector>
#include <string>
#include <unordered_set>
#include <thread>
#include <mutex>

#include "server/server.h"
#include "globals/globals.h"
#include "utils/utils.h"
#include "config/config.h"
#include "webhook/webhook.h"
#include "api/api.h"



#pragma comment(lib, "Ws2_32.lib")

#define MAXBUF  0xFFFF

// Estruturas de cabe�alho
typedef struct {
	UINT8  DstAddr[ 6 ];
	UINT8  SrcAddr[ 6 ];
	UINT16 EthType;
} WINDIVERT_ETHHDR;

// Fun��es utilit�rias
std::string macToStr( UINT8 * mac ) {
	char macStr[ 18 ];
	snprintf( macStr , sizeof( macStr ) , "%02X:%02X:%02X:%02X:%02X:%02X" ,
		mac[ 0 ] , mac[ 1 ] , mac[ 2 ] , mac[ 3 ] , mac[ 4 ] , mac[ 5 ] );
	return std::string( macStr );
}

std::string ipToStr( UINT32 ip ) {
	char ipStr[ 16 ];
	snprintf( ipStr , sizeof( ipStr ) , "%u.%u.%u.%u" ,
		( ip >> 24 ) & 0xFF ,
		( ip >> 16 ) & 0xFF ,
		( ip >> 8 ) & 0xFF ,
		ip & 0xFF );
	return std::string( ipStr );
}

bool isBlockedMAC( const std::unordered_set<std::string> & blockedMACs , const std::string & mac ) {
	return blockedMACs.find( mac ) != blockedMACs.end( );
}

std::string packetToString( const char * data , UINT dataLen ) {
	return std::string( data , dataLen );
}




int main( ) {
	Server connection_server;
	// Inicializa��o


	config::Get( ).LoadConfig( );

	//Login api
	{
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Connecting to the server" ) , GRAY );
		Api::Get( ).Login( );

		if ( !globals::Get( ).LoggedIn ) {
			exit( 0 );
		}
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Connected sucessfully" ) , GREEN );
	}


	HANDLE handle = INVALID_HANDLE_VALUE;
	WINDIVERT_ADDRESS addr;
	char packet[ MAXBUF ];
	UINT packetLen;

	int Error = 0;

	//filter port allocation
	{
		std::vector<std::string> filter { std::string( xorstr_( "udp.DstPort == " ) + std::to_string( config::Get( ).GetCapturePort( ) ) ).c_str( ) };
		// Abertura de handle com filtro
		for ( const auto & f : filter ) {
			handle = WinDivertOpen( f.c_str( ) , WINDIVERT_LAYER_NETWORK , 0 , 0 );
			if ( handle == INVALID_HANDLE_VALUE ) {
				Error = GetLastError( );
			}
		}
	}

	if ( handle == INVALID_HANDLE_VALUE ) {
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Failed to initialize packet capture, error: " ) + std::to_string( Error ) , RED );
		std::this_thread::sleep_for( std::chrono::seconds( 5 ) );
		return -1;
	}

	//utils::Get( ).WarnMessage( _SERVER , xorstr_( "Sucessfully started packet capture on port " ) + std::to_string( config::Get( ).GetCapturePort( ) ) , LIGHT_GREEN );


	std::thread( &Server::threadfunction , &connection_server ).detach( );
	while ( !globals::Get( ).ServerOpen ) {
		std::this_thread::sleep_for( std::chrono::seconds( 1 ) );
	}

	globals::Get( ).whook.SetServerAddress( &connection_server );
	globals::Get( ).whook.InitBot( );


	while ( !globals::Get( ).whook.BotReady ) {
		std::this_thread::sleep_for( std::chrono::seconds( 1 ) );
	}

	globals::Get( ).whook.SendWebHookMessage( xorstr_( "Server initialized!" ) , xorstr_( "Server Message" ) , 0x00FFFF );

	// Armazenar SelfIP localmente
	std::string selfIPStr;
	{
		std::lock_guard<std::mutex> lock( connection_server.connectionMutex );
		selfIPStr = globals::Get( ).SelfIP;
	}

	//Loop de monitoramento de pacotes
	while ( true ) {
		if ( !WinDivertRecv( handle , packet , sizeof( packet ) , &packetLen , &addr ) ) {
			utils::Get( ).WarnMessage( _SERVER , xorstr_( "Failed to capture a packet" ) , RED );
			continue;
		}

		// Declara��es de cabe�alhos
		WINDIVERT_ETHHDR * ethHeader = ( WINDIVERT_ETHHDR * ) packet;
		WINDIVERT_IPHDR * ipHeader = NULL;
		WINDIVERT_TCPHDR * tcpHeader = NULL;
		WINDIVERT_UDPHDR * udpHeader = NULL;
		UINT8 protocol = 0;

		WinDivertHelperParsePacket(
			packet , packetLen , &ipHeader , NULL , &protocol ,
			NULL , NULL , &tcpHeader , &udpHeader , NULL , NULL , NULL , NULL );

		// Processamento de pacotes
		if ( ipHeader != NULL ) {
			std::string srcIPStr = ipToStr( ntohl( ipHeader->SrcAddr ) );

			if ( tcpHeader || udpHeader ) {
				UINT ipHeaderLen = ipHeader->HdrLength * 4;
				UINT transportHeaderLen = tcpHeader ? tcpHeader->HdrLength * 4 : sizeof( WINDIVERT_UDPHDR );
				UINT dataOffset = ipHeaderLen + transportHeaderLen;

				if ( dataOffset < packetLen ) {
					const char * payload = packet + dataOffset;
					UINT payloadLen = packetLen - dataOffset;
					std::string payloadStr = packetToString( payload , payloadLen );
					if ( payloadStr.substr( 0 , 5 ) != xorstr_( "aegis" ) ) {
						bool found = false;
						{
							std::lock_guard<std::mutex> lock( connection_server.connectionMutex );
							found = globals::Get( ).ConnectionMap.find( srcIPStr ) != globals::Get( ).ConnectionMap.end( );
						}
						if ( !found ) continue;
					}
				}
			}
			else {
				bool found = false;
				{
					std::lock_guard<std::mutex> lock( connection_server.connectionMutex );
					found = globals::Get( ).ConnectionMap.find( srcIPStr ) != globals::Get( ).ConnectionMap.end( );
				}
				if ( !found ) continue;
			}
		}


		// Reenvio do pacote
		if ( !WinDivertSend( handle , packet , packetLen , NULL , &addr ) ) {
			std::cerr << xorstr_( "Failed to send packet." ) << std::endl;
		}
	}

	WinDivertClose( handle );
	while ( true ) {
		std::this_thread::sleep_for( std::chrono::seconds( 1 ) );
	}
	return 0;
}
