#include <winsock2.h>
#include <ws2tcpip.h>
#include <comdef.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_set>
#include <utility>

#include <dpp/colors.h>
#include <nlohmann/json.hpp>

#include "server.h"
#include "../config/config.h"
#include "../globals/globals.h"
#include "../image/image.h"
#include "../memory/memory.h"
#include "../utils/utils.h"
#include "../utils/File/File.h"
#include "../webhook/webhook.h"

#pragma comment(lib, "ws2_32.lib")

namespace fs = std::filesystem;
using json = nlohmann::json;



bool CheckHWID( const json & js ) {

	const std::vector<std::string> requiredFields = {
		xorstr_( "mb" ),
		xorstr_( "disk" ),
		xorstr_( "mac" ),
		xorstr_( "ip" ),
		xorstr_( "nickname" ),
		xorstr_( "steamid" ),
		xorstr_( "versionid" )
	};

	for ( const auto & field : requiredFields ) {
		if ( !js.contains( field ) || js[ field ].empty( ) ) {
			utils::Get( ).WarnMessage( _SERVER , xorstr_( "Can't get " ) + field + xorstr_( "!" ) , RED );
			return false;
		}
	}

	return true;
}


CommunicationResponse Server::receivepunish( const std::string & encryptedMessage , CommunicationType type ) {
	if ( encryptedMessage.empty( ) ) {
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Empty message!" ) , RED );
		return RECEIVE_ERROR;
	}

	size_t separator_pos = encryptedMessage.find( "endinfo" );
	if ( separator_pos == std::string::npos ) {
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Separador nao encontrado na string" ) , RED );
		return RECEIVE_ERROR;
	}

	// Separar os segmentos
	std::string encrypted_hwid_and_message = encryptedMessage.substr( 0 , separator_pos );
	std::string raw_image_json = encryptedMessage.substr( separator_pos + std::string( "endinfo" ).length( ) );


	if ( !utils::Get( ).decryptMessage( encrypted_hwid_and_message , encrypted_hwid_and_message , server_key , server_iv ) ) {
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Failed to decrypt punishment message." ) , COLORS::RED );
		return RECEIVE_ERROR;
	}

	json js;

	{
		// Parsing do primeiro JSON (encrypted_hwid_and_message)
		json temp_json;
		try {
			temp_json = json::parse( encrypted_hwid_and_message );
		}
		catch ( const json::parse_error & e ) {
			std::cout << xorstr_( "Failed to parse JSON: " ) << e.what( ) << std::endl;
			return RECEIVE_ERROR;
		}
		js.update( temp_json );  // Mescla os campos no objeto `js`
	}

	{
		// Parsing do segundo JSON (raw_image_json)
		json temp_json;
		try {
			temp_json = json::parse( raw_image_json );
		}
		catch ( const json::parse_error & e ) {
			std::cout << xorstr_( "Failed to parse JSON: " ) << e.what( ) << std::endl;
			return RECEIVE_ERROR;
		}
		js.update( temp_json );  // Mescla os campos no objeto `js`
	}

	// Verificar HWID
	if ( !CheckHWID( js ) ) {
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Can't get hwid!" ) , RED );
		return RECEIVE_ERROR;
	}

	// Verificar campos obrigatórios
	const std::vector<std::string> requiredFields = {
		xorstr_( "image" ),
		xorstr_( "image_width" ),
		xorstr_( "image_height" ),
		xorstr_( "image_hash" ),
		xorstr_( "message" )
	};

	for ( const auto & field : requiredFields ) {
		if ( !js.contains( field ) || js[ field ].empty( ) ) {
			utils::Get( ).WarnMessage( _SERVER , xorstr_( "Can't get " ) + field + xorstr_( "!" ) , RED );
			return RECEIVE_ERROR;
		}
	}

	// Salvar informações da mensagem
	std::string Ip = js[ xorstr_( "ip" ) ];

	// Obter os bytes da imagem e gerar o hash
	std::string ImageHash = js[ xorstr_( "image_hash" ) ];
	std::vector<int> CompressedImage = js[ xorstr_( "image" ) ];


	int height = js[ xorstr_( "image_height" ) ];
	int width = js[ xorstr_( "image_width" ) ];

	//utils::Get( ).WarnMessage( _SERVER , xorstr_( "Reconstructing image!" ) , YELLOW );

	std::string Filename = "";

	// Recriar a imagem
	std::vector<BYTE> Image = image::Get( ).DecompressFromIntermediate( CompressedImage );

	if ( Image.empty( ) ) {
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Failed to decompress image!" ) , RED );
	}
	else {
		std::string Hash = utils::Get( ).GenerateHash( Image );

		// Verificar a integridade da imagem
		if ( ImageHash != Hash ) {
			utils::Get( ).WarnMessage( _SERVER , xorstr_( "Image corrupted!" ) , RED );
		}
		else {
			HBITMAP reconstructedBitmap = image::Get( ).ByteArrayToBitmap( Image , width , height );

			// Criar nome da pasta
			std::string Nickname = js[ xorstr_( "nickname" ) ];
			std::vector<std::string> SteamIDs = js[ xorstr_( "steamid" ) ];
			std::string FolderName = _globals.CurrentPath + "\\Players\\" + Nickname + xorstr_( "-" ) + SteamIDs[ 0 ];

			// Criar diretório se não existir
			if ( !fs::exists( FolderName.c_str( ) ) ) {
				std::this_thread::sleep_for( std::chrono::seconds( 1 ) );
				fs::create_directory( FolderName.c_str( ) );
			}

			// Salvar a imagem
			Filename = FolderName + "\\" + utils::Get( ).GetRandomWord( 20 ) + xorstr_( ".jpg" );
			image::Get( ).SaveBitmapToFile( reconstructedBitmap , Filename );

			// Liberar o recurso HBITMAP
			DeleteObject( reconstructedBitmap );
		}
	}

	// Adicionar o hwid à mensagem
	std::string Message = AppendHWIDToString( js[ xorstr_( "message" ) ] , Ip );

	{
		std::lock_guard<std::mutex> lock( connectionMutex );

		switch ( type ) {
		case BAN:
			WebhookList.emplace_back( WHookRequest( WHOOKTYPE::BAN_ , Message , Filename , Ip , 0 ) );
			if ( !BanPlayer( Ip ) ) {
				utils::Get( ).WarnMessage( _SERVER , xorstr_( "Failed to ban computer banned from server!" ) , RED );
			}
			else {
				utils::Get( ).WarnMessage( _SERVER , xorstr_( "Successfully banned computer banned from server!" ) , GREEN );
			}

			utils::Get( ).WarnMessage( _SERVER , xorstr_( "Sent BAN to webhook request list!" ) , RED );

			break;

		case WARN:
			WebhookList.emplace_back( WHookRequest( WHOOKTYPE::WARN_ , Message , Filename , Ip , 0 ) );

			utils::Get( ).WarnMessage( _SERVER , xorstr_( "Sent WARN to webhook request list!" ) , YELLOW );
			break;

		case SCREENSHOT:
			WebhookList.emplace_back( WHookRequest( WHOOKTYPE::MESSAGE_FILE , Message , Filename , Ip , 0 ) );
			{
				if ( _globals.RequestedScreenshot.find( Ip ) == _globals.RequestedScreenshot.end( ) )
				{
					// If the ip doesnt exist on the requested screenshot set
					utils::Get( ).WarnMessage( _SERVER , xorstr_( "RECEIVED UNREQUESTED SCREENSHOT!" ) , YELLOW );
				}
				else {
					_globals.RequestedScreenshot.erase( Ip );
				}
			}
			utils::Get( ).WarnMessage( _SERVER , xorstr_( "Sent SCREENSHOT to webhook request list!" ) , LIGHT_BLUE );
			break;
		}
	}

	return RECEIVED;
}

CommunicationResponse Server::receivemessage( const std::string & encryptedMessage ) {
	if ( encryptedMessage.empty( ) ) {
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Empty message!" ) , RED );
		return RECEIVE_ERROR;
	}

	json js;
	try {
		js = json::parse( encryptedMessage );
	}
	catch ( const json::parse_error & e ) {
		std::cout << xorstr_( "Failed to parse JSON: " ) << e.what( ) << std::endl;
		return RECEIVE_ERROR;
	}

	if ( !CheckHWID( js ) ) {
		return RECEIVE_ERROR;
	}

	if ( !js.contains( xorstr_( "message" ) ) || js[ xorstr_( "message" ) ].empty( ) ) {
		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Can't get message!" ) , RED );
		return RECEIVE_ERROR;
	}

	std::string Ip = js[ xorstr_( "ip" ) ];
	std::string Message = AppendHWIDToString( js[ xorstr_( "message" ) ] , Ip );

	std::lock_guard<std::mutex> lock( connectionMutex ); // Protege o acesso a ConnectionMap

	WebhookList.emplace_back( WHookRequest( WHOOKTYPE::MESSAGE_ , Message , "" , Ip , dpp::colors::blue_aquamarine ) );

	return RECEIVED;
}



CommunicationResponse Server::receivelogin( const std::string & encryptedMessage ) {



	return RECEIVE_ERROR;
}

CommunicationResponse Server::receiveping( const std::string & encryptedMessage , std::string * IpBuffer ) {
	std::string hardware = encryptedMessage;

	json js;
	try {
		js = json::parse( hardware );
	}
	catch ( const json::parse_error & e ) {
		std::cout << xorstr_( "Failed to parse JSON: " ) << e.what( ) << std::endl;
		return RECEIVE_ERROR;
	}

	if ( !js.contains( xorstr_( "ip" ) ) || js[ xorstr_( "ip" ) ].empty( ) ) {
		return RECEIVE_ERROR;
	}

	std::string Ip = js[ xorstr_( "ip" ) ];


	//create a copy of the connection map, so we wont block requests to the map
	std::unordered_map<std::string , Connection> connectionMap;
	{
		std::lock_guard<std::mutex> lock( connectionMutex );
		connectionMap = _globals.ConnectionMap;
	}

	//No connection on this ip, let's check the hwid to authenticate the player
	bool found = ( connectionMap.find( ( Ip ) ) != connectionMap.end( ) );
	if ( !found ) {

		if ( js.contains( xorstr_( "authentication" ) ) ) {
			utils::Get( ).WarnMessage( _SERVER , xorstr_( "Not Logged user " ) + ( Ip ) +xorstr_( " tried to connect to server!" ) , YELLOW );
			return RECEIVE_NOT_LOGGEDIN;
		}

		if ( !CheckHWID( js ) ) {
			return RECEIVE_ERROR;
		}

		std::vector<std::string> Mac = js[ xorstr_( "mac" ) ];
		std::string DiskID = js[ xorstr_( "disk" ) ];
		std::string MotherboardID = js[ xorstr_( "mb" ) ];
		std::string Nick = js[ xorstr_( "nickname" ) ];
		std::string VersionID = js[ xorstr_( "versionid" ) ];
		std::vector<std::string> Steam = js[ xorstr_( "steamid" ) ];

		if ( IsDiskBanned( DiskID ) || IsBiosBanned( MotherboardID ) || IsMacBanned( Mac ) || IsSteamBanned( Steam ) ) {
			utils::Get( ).WarnMessage( _SERVER , xorstr_( "Banned user " ) + ( Ip ) +xorstr_( " tried to connect to server!" ) , RED );
			return RECEIVE_BANNED;
		}

		if ( VersionID != _globals.VerifiedSessionID && !_globals.NoAuthentication ) {
			utils::Get( ).WarnMessage( _SERVER , xorstr_( "Unverified anticheat on ip " ) + ( Ip ) +xorstr_( " tried to connect to server!" ) , YELLOW );
			return RECEIVE_INVALIDSESSION;
		}

		Connection NewConnection = Connection(
			Nick ,
			Steam ,
			Mac ,
			MotherboardID ,
			DiskID ,
			Ip ,
			time( 0 )
		);
		{
			std::lock_guard<std::mutex> lock( connectionMutex );
			_globals.ConnectionMap[ Ip ] = NewConnection;
		}
		*IpBuffer = Ip;

		utils::Get( ).WarnMessage( _SERVER , xorstr_( "Player " ) + ( Nick ) +xorstr_( ": " ) + Ip + xorstr_( " logged in." ) , GRAY );
		return RECEIVE_LOGGEDIN;
	}
	else {

		if ( !js.contains( xorstr_( "authentication" ) ) || js[ xorstr_( "authentication" ) ].empty( ) ) {
			return RECEIVE_ERROR;
		}

		Connection User = connectionMap[ Ip ];

		std::string Authentication = js[ xorstr_( "authentication" ) ];
		//first ping after loggin
		std::string ExpectedAuth;

		if ( User.GetLastIV( ).empty( ) ) {
			ExpectedAuth = memory::Get( ).GenerateHash( User.GetSessionID( ) + default_encrypt_salt );

			if ( Authentication != ExpectedAuth ) {
				//kick player, wrong auth code
				//std::lock_guard<std::mutex> lock( connectionMutex );
				//_globals.ConnectionMap.erase( Ip );
				utils::Get( ).WarnMessage( _SERVER , xorstr_( "Player " ) + User.GetNickname( ) + xorstr_( " sent " ) + Authentication + xorstr_( ", but expected: " ) + ExpectedAuth , YELLOW );
				return RECEIVED_WRONGAUTH;
			}
		}
		else {
			ExpectedAuth = memory::Get( ).GenerateHash( User.GetLastIV( ) + default_encrypt_salt );

			if ( Authentication != ExpectedAuth ) {
				//kick player, wrong auth code
				//std::lock_guard<std::mutex> lock( connectionMutex );
				//_globals.ConnectionMap.erase( Ip );
				utils::Get( ).WarnMessage( _SERVER , xorstr_( "Player " ) + User.GetNickname( ) + xorstr_( " sent " ) + Authentication + xorstr_( ", but expected: " ) + ExpectedAuth , YELLOW );
				return RECEIVED_WRONGAUTH;
			}
		}

		//we already have this ip connected to the server
		{
			std::lock_guard<std::mutex> lock( connectionMutex );
			_globals.ConnectionMap[ ( Ip ) ].Ping( );
			*IpBuffer = Ip;
		}

		{
			std::lock_guard<std::mutex> lock( ScreenshotMutex );
			if ( _globals.RequestedScreenshot.find( Ip ) != _globals.RequestedScreenshot.end( ) ) {
				return RECEIVED_SCREENSHOTREQUEST;
			}
		}
	}

	return RECEIVED;
}



