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




int main( ) {
    Server connection_server;
    // Inicialização


    config::Get( ).LoadConfig( );

    //Login api
    {
        utils::Get( ).WarnMessage( _SERVER , xorstr_( "Connecting to the server" ) , GRAY );
        Api::Get( ).Login( "admin" , "admin" );

        if ( !globals::Get( ).LoggedIn ) {
            exit( 0 );        
        }
        utils::Get( ).WarnMessage( _SERVER , xorstr_( "Connected sucessfully" ) , GREEN );
    }

    globals::Get( ).whook.SetServerAddress( &connection_server );
    globals::Get( ).whook.InitBot( );


    while ( !globals::Get( ).whook.BotReady ) {
        std::this_thread::sleep_for( std::chrono::seconds( 1 ) );
    }

    globals::Get( ).whook.SendWebHookMessage( "Server initialized!" , "Server Message" , 0x00FFFF );

    std::thread( &Server::threadfunction , &connection_server ).detach( );

    HANDLE handle = INVALID_HANDLE_VALUE;
    WINDIVERT_ADDRESS addr;
    char packet[ MAXBUF ];
    UINT packetLen;
    std::vector<const char *> filter { "true"};

    // Abertura de handle com filtro
    for ( const auto & f : filter ) {
        handle = WinDivertOpen( f , WINDIVERT_LAYER_NETWORK , 0 , 0 );
        if ( handle == INVALID_HANDLE_VALUE ) {
            std::cerr << xorstr_( "Failed to open WinDivert handle with filter: " ) << f
                << xorstr_( ", Error code: " ) << GetLastError( ) << std::endl;
            std::this_thread::sleep_for( std::chrono::seconds( 2 ) );
        }
    }

    if ( handle == INVALID_HANDLE_VALUE ) {
        std::cout << xorstr_( "Can't initialize windivert!\n" );
        std::this_thread::sleep_for( std::chrono::seconds( 5 ) );
        return -1;
    }

    std::cout << xorstr_( "Monitoring incoming packets..." ) << std::endl;

    // Esperar até que SelfIP seja definido
    while ( true ) {
        bool hasSelfIP = false;
        {
            std::lock_guard<std::mutex> lock( connection_server.connectionMutex );
            hasSelfIP = !globals::Get( ).SelfIP.empty( );
        }
        if ( hasSelfIP ) break;
        std::cout << xorstr_( "Waiting for self IP!\n" );
        std::this_thread::sleep_for( std::chrono::seconds( 1 ) );
    }

    // Armazenar SelfIP localmente
    std::string selfIPStr;
    {
        std::lock_guard<std::mutex> lock( connection_server.connectionMutex );
        selfIPStr = globals::Get( ).SelfIP;
    }

    // Loop de monitoramento de pacotes
    while ( true ) {
        if ( !WinDivertRecv( handle , packet , sizeof( packet ) , &packetLen , &addr ) ) {
            std::cerr << xorstr_( "Failed to receive packet." ) << std::endl;
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
            std::string srcIPStr = ipToStr( ntohl( ipHeader->SrcAddr ) );

            if ( srcIPStr != selfIPStr && srcIPStr[ 0 ] == '2' && srcIPStr[ 1 ] == '6' ) {
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
        }

        // Reenvio do pacote
        if ( !WinDivertSend( handle , packet , packetLen , NULL , &addr ) ) {
            std::cerr << xorstr_( "Failed to send packet." ) << std::endl;
        }
    }

    WinDivertClose( handle );
    return 0;
}
