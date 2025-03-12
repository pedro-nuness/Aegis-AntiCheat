#include "globals.h"


globals _globals;


#include "../memory/memory.h"
#include "../utils/utils.h"


void Connection::InitializeSession( ) {
	this->SessionID = utils::Get( ).GenerateRandomKey( 256 );
	this->LastIV = "";
}

void Connection::UpdateIVCode( ) {
	if ( LastIV.empty( ) ) {
		LastIV = memory::Get().GenerateHash( this->SessionID + default_encrypt_salt );
	}
	else {
		LastIV = memory::Get( ).GenerateHash( LastIV + default_encrypt_salt );
	}
}