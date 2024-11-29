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

#include "memory/memory.h"

#pragma comment(lib, "Ws2_32.lib")

#define MAXBUF  0xFFFF

// Estruturas de cabeçalho
typedef struct {
	UINT8  DstAddr[ 6 ];
	UINT8  SrcAddr[ 6 ];
	UINT16 EthType;
} WINDIVERT_ETHHDR;

// Funções utilitárias
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




void IdentifyPacketType( const WINDIVERT_IPHDR * ipHeader ) {
	if ( ipHeader == nullptr ) {
		std::cout << "IP Header is null. Invalid packet." << std::endl;
		return;
	}

	switch ( ipHeader->Protocol ) {
	case IPPROTO_TCP:
		std::cout << "Packet Type: TCP" << std::endl;
		break;
	case IPPROTO_UDP:
		std::cout << "Packet Type: UDP" << std::endl;
		break;
	case IPPROTO_ICMP:
		std::cout << "Packet Type: ICMP" << std::endl;
		break;
	case IPPROTO_IGMP:
		std::cout << "Packet Type: IGMP" << std::endl;
		break;
	default:
		std::cout << "Packet Type: Unknown (" << static_cast< int >( ipHeader->Protocol ) << ")" << std::endl;
		break;
	}
}

void WatchFunction( ) {
	std::string IpWatch;
	std::cout << xorstr_( "Watch Ip Address: " );
	std::cin >> IpWatch;
	std::cout << "\n";

	HANDLE handle = INVALID_HANDLE_VALUE;
	WINDIVERT_ADDRESS addr;
	char packet[ MAXBUF ];
	UINT packetLen;

	int Error = 0;

	//filter port allocation

	std::string filter { xorstr_( "true" ) };
	// Abertura de handle com filtro

	handle = WinDivertOpen( filter.c_str( ) , WINDIVERT_LAYER_NETWORK , 0 , 0 );
	if ( handle == INVALID_HANDLE_VALUE ) {
		std::cout << xorstr_( "Capture open error: " ) << GetLastError( ) << std::endl;
		return;
	}

	std::cout << xorstr_( "Initialized network capture " ) << std::endl;

	while ( true ) {
		if ( !WinDivertRecv( handle , packet , sizeof( packet ) , &packetLen , &addr ) ) {
			utils::Get( ).WarnMessage( _SERVER , xorstr_( "Failed to capture a packet" ) , RED );
			continue;
		}

		// Declarações de cabeçalhos
		WINDIVERT_ETHHDR * ethHeader = ( WINDIVERT_ETHHDR * ) packet;
		WINDIVERT_IPHDR * ipHeader = NULL;
		WINDIVERT_TCPHDR * tcpHeader = NULL;
		WINDIVERT_UDPHDR * udpHeader = NULL;
		UINT8 protocol = 0;

		WinDivertHelperParsePacket(
			packet , packetLen , &ipHeader , NULL , &protocol ,
			NULL , NULL , &tcpHeader , &udpHeader , NULL , NULL , NULL , NULL );

		std::string srcIPStr;

		// Processamento de pacotes
		if ( ipHeader != NULL ) {
			srcIPStr = ipToStr( ntohl( ipHeader->SrcAddr ) );

			if ( srcIPStr == IpWatch ) {
				IdentifyPacketType( ipHeader );
				if ( udpHeader ) {
					std::cout << xorstr_( "SrcPort: " ) << udpHeader->SrcPort << xorstr_( ", DstPort: " ) << udpHeader->DstPort << std::endl;
				}
				std::cout << std::endl;
			}
		}

		// Reenvio do pacote
		if ( !WinDivertSend( handle , packet , packetLen , NULL , &addr ) ) {
			std::cerr << xorstr_( "Failed to send packet." ) << std::endl;
		}
	}
}



int main( int argc , char * argv[ ] ) {

	
	Server connection_server;

	config::Get( ).LoadConfig( );

	//Login api
	{
		Api::Get( ).Login( );

		if ( !globals::Get( ).LoggedIn ) {
			exit( 0 );
			__fastfail( 0 );
		}
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Connected sucessfully" ) , GREEN );
	}


	if ( argc > 1 ) {
		for ( int i = 0; i < argc; i++ ) {
			if ( utils::Get( ).CheckStrings( argv[ i ] , xorstr_( "-watch" ) ) ) {
				WatchFunction( );
				return 1;
			}

			if ( utils::Get( ).CheckStrings( argv[ i ] , xorstr_( "-nolock" ) ) ) {
				globals::Get( ).LockConnections = false;
				utils::Get( ).WarnMessage( _SERVER , xorstr_( "Server initializing on no lock mode" ) , YELLOW );
			}

			if ( utils::Get( ).CheckStrings( argv[ i ] , xorstr_( "-nobot" ) ) ) {
				globals::Get( ).Usebot = false;
				utils::Get( ).WarnMessage( _SERVER , xorstr_( "Server initializing on no bot mode" ) , YELLOW );
			}
		}
	}


	//filter port allocation

	std::thread( &Server::threadfunction , &connection_server ).detach( );
	while ( !globals::Get( ).ServerOpen ) {
		std::this_thread::sleep_for( std::chrono::seconds( 1 ) );
	}

	if ( globals::Get( ).Usebot ) {

		globals::Get( ).whook.SetServerAddress( &connection_server );
		globals::Get( ).whook.InitBot( );


		while ( !globals::Get( ).whook.BotReady ) {
			std::this_thread::sleep_for( std::chrono::seconds( 1 ) );
		}

		globals::Get( ).whook.SendWebHookMessage( xorstr_( "Server initialized!" ) , xorstr_( "Server Message" ) , 0x00FFFF );
	}



	if ( globals::Get( ).LockConnections ) {

		HANDLE handle = INVALID_HANDLE_VALUE;
		WINDIVERT_ADDRESS addr;
		char packet[ MAXBUF ];
		UINT packetLen;

		int Error = 0;

		// Armazenar SelfIP localmente
		std::string selfIPStr;
		{
			std::lock_guard<std::mutex> lock( connection_server.connectionMutex );
			selfIPStr = globals::Get( ).SelfIP;
		}

		{
			std::string DefaultFilter;
			DefaultFilter += xorstr_( "true" );

			std::vector<std::string> filter { DefaultFilter };
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


		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Sucessfully started packet capture on port " ) + std::to_string( config::Get( ).GetCapturePort( ) ) , LIGHT_GREEN );

		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Self IP: " ) + selfIPStr , GRAY );


		//Loop de monitoramento de pacotes
		while ( true ) {
			if ( !WinDivertRecv( handle , packet , sizeof( packet ) , &packetLen , &addr ) ) {
				utils::Get( ).WarnMessage( _SERVER , xorstr_( "Failed to capture a packet" ) , RED );
				continue;
			}

			// Declarações de cabeçalhos
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
				std::string srcIPStr;
				srcIPStr = ipToStr( ntohl( ipHeader->SrcAddr ) );
				if ( udpHeader ) {

					if ( udpHeader->DstPort == config::Get( ).GetCapturePort( ) ) {
						bool found = false;
						{
							std::lock_guard<std::mutex> lock( connection_server.connectionMutex );
							found = globals::Get( ).ConnectionMap.find( srcIPStr ) != globals::Get( ).ConnectionMap.end( );
						}
						if ( !found ) {
							//utils::Get( ).WarnMessage( _SERVER , xorstr_( "blocked packet from " ) + srcIPStr , RED );
							continue;
						}
					}
				}
			}

			// Reenvio do pacote
			if ( !WinDivertSend( handle , packet , packetLen , NULL , &addr ) ) {
				std::cerr << xorstr_( "Failed to send packet." ) << std::endl;
			}
		}

		WinDivertClose( handle );
	}
	while ( true ) {
		std::this_thread::sleep_for( std::chrono::seconds( 1 ) );
	}
	return 0;
}
