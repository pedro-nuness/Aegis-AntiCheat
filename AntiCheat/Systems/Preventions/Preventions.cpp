#include "Preventions.h"

#include <Windows.h>    
#include <Aclapi.h>     
#include <sddl.h>       
#include <tchar.h>      




bool Preventions::RestrictProcessAccess( ) {
	HANDLE hProcess = GetCurrentProcess( );
	PSECURITY_DESCRIPTOR pSD = NULL;
	PACL pOldDACL = NULL , pNewDACL = NULL;
	EXPLICIT_ACCESS ea = { 0 };
	PSID pEveryoneSID = NULL;
	SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;


	if ( GetSecurityInfo( hProcess , SE_KERNEL_OBJECT , DACL_SECURITY_INFORMATION ,
		NULL , NULL , &pOldDACL , NULL , &pSD ) != ERROR_SUCCESS ) {
		return false;
	}


	if ( !AllocateAndInitializeSid( &SIDAuthWorld , 1 ,
		SECURITY_WORLD_RID ,
		0 , 0 , 0 , 0 , 0 , 0 , 0 ,
		&pEveryoneSID ) ) {
		if ( pSD ) LocalFree( pSD );
		return false;
	}

	ea.grfAccessPermissions = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE;
	ea.grfAccessMode = DENY_ACCESS;
	ea.grfInheritance = NO_INHERITANCE;
	ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	ea.Trustee.ptstrName = ( LPSTR ) pEveryoneSID;

	if ( SetEntriesInAcl( 1 , &ea , pOldDACL , &pNewDACL ) != ERROR_SUCCESS ) {
		if ( pSD ) LocalFree( pSD );
		if ( pEveryoneSID ) FreeSid( pEveryoneSID );
		return false;
	}

	if ( SetSecurityInfo( hProcess , SE_KERNEL_OBJECT , DACL_SECURITY_INFORMATION ,
		NULL , NULL , pNewDACL , NULL ) != ERROR_SUCCESS ) {
		if ( pSD ) LocalFree( pSD );
		if ( pEveryoneSID ) FreeSid( pEveryoneSID );
		if ( pNewDACL ) LocalFree( pNewDACL );
		return false;
	}

	if ( pSD ) LocalFree( pSD );
	if ( pEveryoneSID ) FreeSid( pEveryoneSID );
	if ( pNewDACL ) LocalFree( pNewDACL );

	return true;
}