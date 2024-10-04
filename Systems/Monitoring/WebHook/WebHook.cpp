#include "WebHook.h"
#include <dpp/dpp.h>
#include <thread>

#include "../../Utils/xorstr.h"
#include "../../Utils/StringCrypt/StringCrypt.h"
#include "../../Utils/XorString/XorString.h"

dpp::cluster webhook( "" ); // normally, you put your bot token in here. But to just run a webhook its not required

void WebHook::SendWebHookMessage( std::string Message, uint32_t Color ) {

    // Create an embed
    dpp::embed embed;
    embed.set_color( Color == NULL ? dpp::colors::cyan : Color )
        .set_title( xorstr_( "AegisUAC" ) )
        .set_thumbnail( xorstr_( "https://raw.githubusercontent.com/pedro-nuness/pedro-nuness/main/aegis.webp" ) )
        .set_description( xorstr_( "Created by pedro.nuness | Kun#6394" ) )
        .add_field( xorstr_( "AntiCheat Message" ) , Message , true )
        .set_timestamp( time( 0 ) );

    dpp::message msg;
    msg.add_embed( embed );
  
   // Send the message with this webhook
    std::string * DecryptedString = StringCrypt::Get( ).DecryptString( this->wHook );
    webhook.execute_webhook( dpp::webhook( *DecryptedString ) , msg );
    StringCrypt::Get( ).CleanString( DecryptedString );
}

void WebHook::SendWebHookMessageWithFile( std::string Message,std::string Filename, uint32_t Color ) {

    // Create an embed
    dpp::embed embed;
    embed.set_color( Color == NULL ? dpp::colors::red : Color )
        .set_title( xorstr_("Aegis UAC") )
        .set_thumbnail( xorstr_("https://raw.githubusercontent.com/pedro-nuness/pedro-nuness/main/aegis.webp") )
        .set_description( xorstr_("Created by pedro.nuness | Kun#6394") )
        .add_field( xorstr_("AntiCheat SCREENSHOT") , Message , true )
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
    StringCrypt::Get( ).CleanString( DecryptedString );
}





