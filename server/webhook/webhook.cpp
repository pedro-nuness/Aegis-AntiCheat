#include "webhook.h"

#include <dpp/dpp.h>

#include <thread>
#include <iostream>
#include <exception> // Para manipulação de exceções

#include "../utils/utils.h"
#include "../server/server.h"
#include "../config/config.h"

std::string ban_prefix = "_ban";
std::string unban_prefix = "unban";

#include <nlohmann/json.hpp>

using json = nlohmann::json;

WebHook::WebHook( ) {
	this->wHook = config::Get( ).GetBotToken( );
	this->BOT = nullptr;
	this->ServerPtr = nullptr;
}


void WebHook::SendWebHookPunishMent( std::string Message , std::string ScreenshotPath , std::string IP , bool already_banned ) {
	try {
		utils::Get( ).WarnMessage( WEBHOOK , xorstr_( "Sending webhook message" ) , LIGHTER_BLUE );

		json js;
		try {
			js = json::parse( Message );
		}
		catch ( const json::parse_error & e ) {
			std::cout << xorstr_( "Failed to parse JSON: " ) << e.what( ) << std::endl;
			return;
		}


		// Criar um embed
		dpp::embed embed;
		embed.set_color( already_banned ? dpp::colors::red : dpp::colors::yellow )
			.set_title( ( "AegisUAC" ) )
			.set_thumbnail( ( "https://raw.githubusercontent.com/pedro-nuness/pedro-nuness/main/aegis.webp" ) )
			.set_description( ( "Created by pedro.nuness | Kun#6394" ) )
			.add_field( ( "Player Identifier" ) , js[ xorstr_( "hwid" ) ] , true )
			.add_field( ( "AntiCheat Message" ) , js[ xorstr_( "message" ) ] , true )
			.set_timestamp( time( 0 ) );

		dpp::message msg( config::Get( ).GetDiscordChannel( ) , "" );
		msg.add_embed( embed );

		// Ler o arquivo e adicioná-lo à mensagem
		std::string File = dpp::utility::read_file( ScreenshotPath );
		msg.add_file( ScreenshotPath , File );

		msg.add_component(
			dpp::component {}.add_component(
				dpp::component {}
				.set_type( dpp::cot_button )
				.set_label( already_banned ? "Unban player" : "Ban player" )
				.set_id( already_banned ? unban_prefix + IP : ban_prefix + IP )
				.set_style( already_banned ? dpp::cos_success : dpp::cos_danger )
			)
		);

		// Enviar a mensagem com o webhook= 
		reinterpret_cast< dpp::cluster * >( this->BOT )->message_create( msg );
		utils::Get( ).WarnMessage( WEBHOOK , xorstr_( "Webhook message sent sucessfuly" ) , GREEN );
	}
	catch ( const std::exception & e ) {
		std::cerr << "Erro ao enviar webhook: " << e.what( ) << std::endl;
	}
	catch ( ... ) {
		std::cerr << "Erro desconhecido ao enviar webhook." << std::endl;
	}


}

void WebHook::SendWebHookMessage( std::string Message , std::string TOPIC , uint32_t Color ) {
	try {

		utils::Get( ).WarnMessage( WEBHOOK , xorstr_( "Sending webhook message" ) , LIGHTER_BLUE );

		std::string Identifier = xorstr_( "Server Message" );
		std::string MSG = Message;

		json js;
		try {
			js = json::parse( Message );
		}
		catch ( const json::parse_error & e ) {
		}

		if ( !js.empty( ) ) {
			if ( !js.contains( xorstr_( "message" ) ) || !js.contains( xorstr_( "hwid" ) ) ) {
				utils::Get( ).WarnMessage( WEBHOOK , xorstr_( "Invalid message format!" ) , RED );
				return;
			}

			MSG = js[ xorstr_( "message" ) ];
			Identifier = js[ xorstr_( "hwid" ) ];
		}

		// Criar um embed
		dpp::embed embed;
		embed.set_color( Color == NULL ? dpp::colors::cyan : Color )
			.set_title( ( "AegisUAC" ) )
			.set_thumbnail( ( "https://raw.githubusercontent.com/pedro-nuness/pedro-nuness/main/aegis.webp" ) )
			.set_description( ( "Created by pedro.nuness | Kun#6394" ) )
			.add_field( ( "Player Identifier" ) , Identifier , true )
			.add_field( ( "AntiCheat Message" ) , MSG , true )
			.set_timestamp( time( 0 ) );


		dpp::message msg( config::Get( ).GetDiscordChannel( ) , "" );
		msg.add_embed( embed );

		// Enviar a mensagem com o webhook= 
		reinterpret_cast< dpp::cluster * >( this->BOT )->message_create( msg );

		utils::Get( ).WarnMessage( WEBHOOK , xorstr_( "Webhook message sent sucessfuly" ) , GREEN );
	}
	catch ( const std::exception & e ) {
		std::cerr << "Erro ao enviar webhook: " << e.what( ) << std::endl;
	}
	catch ( ... ) {
		std::cerr << "Erro desconhecido ao enviar webhook." << std::endl;
	}
}

void WebHook::SendWebHookMessageWithFile( std::string Message , std::string Filename , std::string IP , uint32_t Color ) {
	try {

		json js;
		try {
			js = json::parse( Message );
		}
		catch ( const json::parse_error & e ) {
			std::cout << xorstr_( "Failed to parse JSON: " ) << e.what( ) << std::endl;
			return;
		}

		// Criar um embed
		utils::Get( ).WarnMessage( WEBHOOK , xorstr_( "Sending webhook message" ) , LIGHTER_BLUE );
		dpp::embed embed;
		embed.set_color( Color == NULL ? dpp::colors::red : Color )
			.set_title( ( "Aegis UAC" ) )
			.set_thumbnail( ( "https://raw.githubusercontent.com/pedro-nuness/pedro-nuness/main/aegis.webp" ) )
			.set_description( ( "Created by pedro.nuness | Kun#6394" ) )
			.add_field( ( "Player Identifier" ) , js[ xorstr_( "hwid" ) ] , true )
			.add_field( ( "AntiCheat Message" ) , js[ xorstr_( "message" ) ] , true )
			.set_timestamp( time( 0 ) );

		dpp::message msg( config::Get( ).GetDiscordChannel( ) , "" );
		msg.add_embed( embed );

		// Ler o arquivo e adicioná-lo à mensagem
		std::string File = dpp::utility::read_file( Filename );
		msg.add_file( Filename , File );

		// Enviar a mensagem com o webhook= 
		reinterpret_cast< dpp::cluster * >( this->BOT )->message_create( msg );

		utils::Get( ).WarnMessage( WEBHOOK , xorstr_( "Webhook message sent sucessfuly" ) , GREEN );
	}
	catch ( const std::exception & e ) {
		std::cerr << "Erro ao enviar webhook com arquivo: " << e.what( ) << std::endl;
	}
	catch ( ... ) {
		std::cerr << "Erro desconhecido ao enviar webhook com arquivo." << std::endl;
	}
}



void WebHook::BanIp( std::string IP ) {

}

void WebHook::UnbanIp( std::string IP ) {

}



void WebHook::Start( ) {
	/* Create the bot */
	dpp::cluster bot( this->wHook );

	this->BOT = &bot;

	/* The event is fired when someone issues your commands */
	bot.on_slashcommand( [ this , &bot ] ( const dpp::slashcommand_t & event ) {
		/* Check which command they ran */
		if ( event.command.channel_id != config::Get( ).GetDiscordChannel( ) ) {
			event.reply( xorstr_( "Sorry, but i can't answer your request!" ) );
			return;
		}

		if ( event.command.get_command_name( ) == "screenshot" ) {
			std::string ip = std::get<std::string>( event.get_parameter( "ip" ) );

			std::string Response = reinterpret_cast< Server * >( this->GetServerPTR( ) )->RequestScreenshotFromClient( ip );

			/*std::vector<dpp::snowflake> Roles = event.command.member.get_roles( );
			for ( auto Role : Roles ) {
				Response += Role.str( ) + ", ";
			}*/

			dpp::message msg( event.command.channel_id , Response );

			/* Reply to the user with the message, with our file attached. */
			event.reply( msg );
		}

		if ( event.command.get_command_name( ) == "listplayers" ) {

			std::string Response = reinterpret_cast< Server * >( this->GetServerPTR( ) )->GetConnectedPlayers( );

			dpp::embed embed;
			embed.set_color( dpp::colors::aquamarine_stone )
				.set_title( ( "Aegis UAC" ) )
				.set_thumbnail( ( "https://raw.githubusercontent.com/pedro-nuness/pedro-nuness/main/aegis.webp" ) )
				.set_description( ( "Created by pedro.nuness | Kun#6394" ) )
				.add_field( ( "Connection list" ) , Response , true )
				.set_timestamp( time( 0 ) );

			dpp::message msg( event.command.channel_id , "" );
			msg.add_embed( embed );

			/* Reply to the user with the message, with our file attached. */
			event.reply( msg );
		}


		if ( event.command.get_command_name( ) == "ban" ) {

			std::string ip = std::get<std::string>( event.get_parameter( "ip" ) );

			utils::Get( ).WarnMessage( WEBHOOK , xorstr_( "received ban command to ip: " ) + ip , YELLOW );

			std::string Response;
			bool Success = reinterpret_cast< Server * >( this->GetServerPTR( ) )->RequestBanIP( ip , &Response );

			// Escolher a cor com base no sucesso ou falha
			uint32_t color = Success ? dpp::colors::light_red : dpp::colors::dark_red;

			dpp::embed embed;
			embed.set_color( color )
				.set_title( "Aegis UAC" )
				.set_thumbnail( "https://raw.githubusercontent.com/pedro-nuness/pedro-nuness/main/aegis.webp" )
				.set_description( "Created by pedro.nuness | Kun#6394" )
				.add_field( "Connection list" , Response , true )
				.set_timestamp( time( 0 ) );

			dpp::message msg( event.command.channel_id , "" );
			msg.add_embed( embed );

			// Responder ao usuário com a mensagem
			event.reply( msg );
		}

		if ( event.command.get_command_name( ) == "unban" ) {


			std::string ip = std::get<std::string>( event.get_parameter( "ip" ) );

			utils::Get( ).WarnMessage( WEBHOOK , xorstr_( "received unban command to ip: " ) + ip , YELLOW );

			std::string Response;
			bool Success = reinterpret_cast< Server * >( this->GetServerPTR( ) )->RequestUnbanIp( ip , &Response );

			// Escolher a cor com base no sucesso ou falha
			uint32_t color = Success ? dpp::colors::light_green : dpp::colors::dark_green;

			dpp::embed embed;
			embed.set_color( color )
				.set_title( "Aegis UAC" )
				.set_thumbnail( "https://raw.githubusercontent.com/pedro-nuness/pedro-nuness/main/aegis.webp" )
				.set_description( "Created by pedro.nuness | Kun#6394" )
				.add_field( "Connection list" , Response , true )
				.set_timestamp( time( 0 ) );

			dpp::message msg( event.command.channel_id , "" );
			msg.add_embed( embed );

			// Responder ao usuário com a mensagem
			event.reply( msg );
		}

		} );

	bot.on_ready( [ &bot, this ] ( const dpp::ready_t & event ) {

		/* Create and register a command when the bot is ready */


		if ( dpp::run_once<struct register_bot_commands>( ) ) {
			dpp::slashcommand ScreenshotCommand( "screenshot" , "get a screnshot of a player" , bot.me.id );
			ScreenshotCommand.add_option(
				dpp::command_option( dpp::co_string , "ip" , "player ip" , true )
			);

			dpp::slashcommand BanCommand( "ban" , "Ban player" , bot.me.id );
			BanCommand.add_option(
				dpp::command_option( dpp::co_string , "ip" , "player ip" , true )
			);

			dpp::slashcommand UnbanCommand( "unban" , "Unban player" , bot.me.id );
			UnbanCommand.add_option(
				dpp::command_option( dpp::co_string , "ip" , "player ip" , true )
			);

			dpp::slashcommand ListPlayersCommand( "listplayers" , "Generate a list of the connected players" , bot.me.id );

			bot.global_command_create( ScreenshotCommand );
			bot.global_command_create( ListPlayersCommand );
			bot.global_command_create( BanCommand );
			bot.global_command_create( UnbanCommand );

			this->BotReady = true;
		}
		} );


	bot.on_button_click( [ this , &bot ] ( const dpp::button_click_t & event ) {
		std::string ID = event.custom_id;
		CommunicationType TYPE = NONE;
		std::string message;
		bool Success = false;

		// Função auxiliar para manipular prefixos
		auto handle_prefix = [ & ] ( const std::string & prefix , CommunicationType type , const std::string & action ) {
			size_t pos = ID.find( prefix );
			if ( pos != std::string::npos ) {
				ID.erase( pos , prefix.length( ) );
				TYPE = type;
				utils::Get( ).WarnMessage( WEBHOOK , xorstr_( "received " ) + action + xorstr_( " command to ip: " ) + ID , YELLOW );
				return true;
			}
			return false;
			};

		if ( handle_prefix( ban_prefix , BAN , "ban" ) ) {
			Success = reinterpret_cast< Server * >( this->GetServerPTR( ) )->RequestBanIP( ID , &message );
		}
		else if ( handle_prefix( unban_prefix , UNBAN , "unban" ) ) {
			Success = reinterpret_cast< Server * >( this->GetServerPTR( ) )->RequestUnbanIp( ID , &message );
		}

		if ( TYPE == NONE ) {
			event.reply( "Invalid command ID!" );
			return;
		}

		// Mapeamento de cores e estilos
		std::unordered_map<CommunicationType , std::pair<uint32_t , uint8_t>> style_map = {
			{BAN, {Success ? dpp::colors::light_red : dpp::colors::dark_red, dpp::cos_danger}},
			{UNBAN, {Success ? dpp::colors::light_green : dpp::colors::dark_green, dpp::cos_success}}
		};

		auto [Color , ButtonStyle] = style_map[ TYPE ];

		// Criação do embed
		dpp::embed embed;
		embed.set_color( Color )
			.set_title( "Aegis UAC" )
			.set_thumbnail( "https://raw.githubusercontent.com/pedro-nuness/pedro-nuness/main/aegis.webp" )
			.set_description( "Created by pedro.nuness | Kun#6394" )
			.add_field( "Ban event" , message , true )
			.set_timestamp( time( 0 ) );

		dpp::message msg( config::Get( ).GetDiscordChannel( ) , "" );
		msg.add_embed( embed );

		// Somente adicionar o botão se o comando for bem-sucedido
		if ( Success ) {
			std::string Button_ID = ( TYPE == BAN ? unban_prefix : ban_prefix ) + ID;
			std::string Button_Name = ( TYPE == BAN ? xorstr_( "Unban " ) : xorstr_( "Ban " ) ) + ID;

			msg.add_component(
				dpp::component {}.add_component(
					dpp::component {}
					.set_type( dpp::cot_button )
					.set_label( Button_Name )
					.set_style( static_cast< dpp::component_style >( ButtonStyle ) )
					.set_id( Button_ID )
				)
			);
		}

		event.reply( msg );
		} );


	bot.on_log( dpp::utility::cout_logger( ) );
	



	bot.start( dpp::st_wait );
}

void WebHook::InitBot( ) {
	std::thread( &WebHook::Start , this ).detach( );
}