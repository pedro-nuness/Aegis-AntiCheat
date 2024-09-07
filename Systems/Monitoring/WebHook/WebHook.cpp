#include "WebHook.h"
#include <dpp/dpp.h>

#include "../../Utils/crypt_str.h"
#include "../../Utils/StringCrypt/StringCrypt.h"


dpp::cluster webhook( "" ); // normally, you put your bot token in here. But to just run a webhook its not required


void WebHook::SendWebHookMessage( std::string Message, uint32_t Color ) {

    // Create an embed
    dpp::embed embed;
    embed.set_color( Color == NULL ? dpp::colors::cyan : Color )
        .set_title( crypt_str( "AegisUAC" ) )
        .set_thumbnail( crypt_str( "https://raw.githubusercontent.com/pedro-nuness/pedro-nuness/main/aegis.webp" ) )
        .set_description( crypt_str( "Created by pedro.nuness | Kun#6394" ) )
        .add_field( crypt_str( "AntiCheat Message" ) , Message , true )
        .set_timestamp( time( 0 ) );

    dpp::message msg;
    msg.add_embed( embed );

    // Send the message with this webhook
    std::string * DecryptedString = StringCrypt::Get( ).DecryptString( this->wHook );
    webhook.execute_webhook( dpp::webhook( *DecryptedString ) , msg );

    std::fill( DecryptedString->begin( ) , DecryptedString->end( ) , 0 );
    delete DecryptedString;
}

void WebHook::SendWebHookMessageWithFile( std::string Message,std::string Filename, uint32_t Color ) {
    std::cout << "wHook: " << this->wHook << "\n";

    // Create an embed
    dpp::embed embed;
    embed.set_color( Color == NULL ? dpp::colors::red : Color )
        .set_title( crypt_str("Aegis UAC") )
        .set_thumbnail( crypt_str("https://raw.githubusercontent.com/pedro-nuness/pedro-nuness/main/aegis.webp") )
        .set_description( crypt_str("Created by pedro.nuness | Kun#6394") )
        .add_field( crypt_str("AntiCheat SCREENSHOT") , Message , true )
        .set_timestamp( time( 0 ) );

    // Add the row component to the message
    dpp::message msg;
    msg.add_embed( embed );

    // Read the file and add it to the message
    std::string File = dpp::utility::read_file( Filename );
    msg.add_file( Filename , File );

    // Send the message with this webhook
    std::string * DecryptedString = StringCrypt::Get( ).DecryptString( this->wHook );
    webhook.execute_webhook( dpp::webhook( *DecryptedString ) , msg );

    std::fill( DecryptedString->begin( ) , DecryptedString->end( ) , 0 );
    delete DecryptedString;
}





