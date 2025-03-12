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

#include "utils/File/File.h"

#include "memory/memory.h"

#include <filesystem>

#pragma comment(lib, "Ws2_32.lib")

#define MAXBUF  0xFFFF

namespace fs = std::filesystem;

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

void ReloadConfigThread( ) {
	utils::Get( ).WarnMessage( _SERVER , xorstr_( "Reload config thread started! Press F5 to reload config / session ID / Whitelist!" ) , GREEN );
	bool PressedReloadKey = false;
	while ( true ) {
		if ( GetAsyncKeyState( VK_F5 ) & 1 && !PressedReloadKey) {
			_config.LoadConfig( );

			std::string VerifiedSessionID = "";

			//Login api
			{
				if ( Api::Get( ).Login( &VerifiedSessionID ) ) {
					_globals.VerifiedSessionID = VerifiedSessionID;
				}

				if ( !_globals.LoggedIn ) {
					exit( 0 );
					__fastfail( 0 );
				}
				utils::Get( ).WarnMessage( _SERVER , xorstr_( "Reloaded successfully" ) , GREEN );
			}

			PressedReloadKey = true;
		}
		else if ( PressedReloadKey ) {
			PressedReloadKey = false;
		}

		std::this_thread::sleep_for( std::chrono::milliseconds( 250 ) );
	}
}


void UpdateSessionID( ) {
	std::string SessionID;
	std::cout << "SessionID: ";
	std::cin >> SessionID;
	std::cout << "\n";

	std::string Response;
	if( !Api::Get( ).UpdateSessionID( &Response , SessionID ) ) {
		std::cout << "Request failed!\n";
	}
	else {
		std::cout << "Sent request sucessfully!\n";
	}

	std::cout << Response << std::endl;
	system( "pause" );
}

void GenerateSessionID( ) {
	std::string AntiCheatVersionID = memory::Get( ).GetFileHash( xorstr_("aegis.exe" ));
	if ( AntiCheatVersionID.empty( ) )
		return;

	std::string ParentVersionID = memory::Get( ).GetFileHash( xorstr_( "parent.exe" ) );

	if ( ParentVersionID.empty( ) )
		return;

	std::string GameVersionID = memory::Get( ).GetFileHash( xorstr_( "game.exe" ) );

	if ( GameVersionID.empty( ) )
		return;

	std::string FinalVersionID = memory::Get( ).GenerateHash( AntiCheatVersionID + ParentVersionID + GameVersionID );

	File newfile( xorstr_( "output.txt" ) );
	newfile.Write( FinalVersionID );
}


void ShowHelp( ) {
	std::cout << "Available Commands:\n";
	std::cout << "  -us         : Updates the session ID.\n";
	std::cout << "  -watch      : Executes the watch function.\n";
	std::cout << "  -nolock     : Disables connection locking.\n";
	std::cout << "                Warning: This may reduce security.\n";
	std::cout << "  -noauth     : Disables authentication.\n";
	std::cout << "                Warning: This may allow unauthorized access.\n";
	std::cout << "  -nobot      : Disables bot usage in the server.\n";
	std::cout << "  -gs         : Generates session id, game.exe, aegis.exe and parent.exe must be on the folder!\n";
	std::cout << "  -help       : Displays this help message.\n";
}



int main( int argc , char * argv[ ] ) {



	Server connection_server;

	_config.LoadConfig( );

	std::string VerifiedSessionID = "";

	//Login api
	{
		if ( Api::Get( ).Login( &VerifiedSessionID ) ) {
			_globals.VerifiedSessionID = VerifiedSessionID;
		}

		if ( !_globals.LoggedIn ) {
			exit( 0 );
			__fastfail( 0 );
		}
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Connected sucessfully" ) , GREEN );
	}

	utils::Get( ).WarnMessage( _SERVER , xorstr_( "Authentic SessionID: " ) + _globals.VerifiedSessionID , GREEN );


	if ( argc > 1 ) {
		for ( int i = 0; i < argc; i++ ) {
			if ( utils::Get( ).CheckStrings( argv[ i ] , xorstr_( "-us" ) ) ) {
				UpdateSessionID( );
				return 1;
			}

			if ( utils::Get( ).CheckStrings( argv[ i ] , xorstr_( "-gs" ) ) ) {
				GenerateSessionID( );
				return 1;
			}


			if ( utils::Get( ).CheckStrings( argv[ i ] , xorstr_( "-watch" ) ) ) {
				WatchFunction( );
				return 1;
			}

			if ( utils::Get( ).CheckStrings( argv[ i ] , xorstr_( "-nolock" ) ) ) {
				_globals.LockConnections = false;
				utils::Get( ).WarnMessage( _SERVER , xorstr_( "Server initializing on no lock mode" ) , YELLOW );
				continue;
			}

			if ( utils::Get( ).CheckStrings( argv[ i ] , xorstr_( "-noauth" ) ) ) {
				_globals.NoAuthentication = true;
				utils::Get( ).WarnMessage( _SERVER , xorstr_( "Server initializing on no authentication mode" ) , YELLOW );
				continue;
			}

			if ( utils::Get( ).CheckStrings( argv[ i ] , xorstr_( "-nobot" ) ) ) {
				_globals.Usebot = false;
				utils::Get( ).WarnMessage( _SERVER , xorstr_( "Server initializing on no bot mode" ) , YELLOW );
				continue;
			}

			if ( utils::Get( ).CheckStrings( argv[ i ] , xorstr_( "-help" ) ) ) {
				ShowHelp( );
				return 0;
			}
		}
	}

	std::thread( ReloadConfigThread ).detach( );
	_globals.CurrentPath = memory::Get( ).GetProcessPath( ::_getpid( ) );
	if ( !fs::exists( _globals.CurrentPath + xorstr_( "\\Players" ) ) ) {
		fs::create_directory( _globals.CurrentPath + xorstr_( "\\Players" ) );
	}


	//filter port allocation

	std::thread( &Server::threadfunction , &connection_server ).detach( );
	while ( !_globals.ServerOpen ) {
		std::this_thread::sleep_for( std::chrono::seconds( 1 ) );
	}

	if ( _globals.Usebot ) {

		_globals.whook.SetServerAddress( &connection_server );
		_globals.whook.InitBot( );


		while ( !_globals.whook.BotReady ) {
			std::this_thread::sleep_for( std::chrono::seconds( 1 ) );
		}

		_globals.whook.SendWebHookMessage( xorstr_( "Server initialized!" ) , xorstr_( "Server Message" ) , 0x00FFFF );
	}



	if ( _globals.LockConnections ) {

		HANDLE handle = INVALID_HANDLE_VALUE;
		WINDIVERT_ADDRESS addr;
		char packet[ MAXBUF ];
		UINT packetLen;

		int Error = 0;

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


		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Sucessfully started packet capture on port " ) + std::to_string( _config.GetCapturePort( ) ) , LIGHT_GREEN );



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

					if ( udpHeader->DstPort == _config.GetCapturePort( ) ) {
						bool found = false;
						{
							std::lock_guard<std::mutex> lock( connection_server.connectionMutex );
							found = _globals.ConnectionMap.find( srcIPStr ) != _globals.ConnectionMap.end( );
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
