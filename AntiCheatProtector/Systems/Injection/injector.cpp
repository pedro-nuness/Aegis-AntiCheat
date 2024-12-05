#include "Injection.h"
#include "injector.h"

#include "../Utils/xorstr.h"
#if defined(DISABLE_OUTPUT)
#define ILog( data, ...)
#else
#define ILog( text, ...) printf(text, __VA_ARGS__);
#endif
#include <vector>

#ifdef _WIN64
#define CURRENT_ARCH IMAGE_FILE_MACHINE_AMD64
#else
#define CURRENT_ARCH IMAGE_FILE_MACHINE_I386
#endif

bool Injector::ManualMapDll( HANDLE hProc , BYTE * pSrcData , SIZE_T FileSize , bool ClearHeader , bool ClearNonNeededSections , bool AdjustProtections , bool SEHExceptionSupport , DWORD fdwReason , LPVOID lpReserved ) {
	IMAGE_NT_HEADERS * pOldNtHeader = nullptr;
	IMAGE_OPTIONAL_HEADER * pOldOptHeader = nullptr;
	IMAGE_FILE_HEADER * pOldFileHeader = nullptr;
	BYTE * pTargetBase = nullptr;

	if ( reinterpret_cast< IMAGE_DOS_HEADER * >( pSrcData )->e_magic != 0x5A4D ) { //"MZ"
		ILog( xorstr_( "Invalid file\n" ) );
		return false;
	}


	pOldNtHeader = reinterpret_cast< IMAGE_NT_HEADERS * >( pSrcData + reinterpret_cast< IMAGE_DOS_HEADER * >( pSrcData )->e_lfanew );
	pOldOptHeader = &pOldNtHeader->OptionalHeader;
	pOldFileHeader = &pOldNtHeader->FileHeader;

	if ( pOldFileHeader->Machine != CURRENT_ARCH ) {
		ILog( xorstr_( "Invalid platform\n" ) );
		return false;
	}

	//	ILog( xorstr_("File ok\n");

	pTargetBase = reinterpret_cast< BYTE * >( VirtualAllocEx( hProc , nullptr , pOldOptHeader->SizeOfImage , MEM_COMMIT | MEM_RESERVE , PAGE_READWRITE ) );
	if ( !pTargetBase ) {
		ILog( xorstr_( "Target process memory allocation failed (ex) 0x%X\n" ) , GetLastError( ) );
		return false;
	}

	DWORD oldp = 0;
	VirtualProtectEx( hProc , pTargetBase , pOldOptHeader->SizeOfImage , PAGE_EXECUTE_READWRITE , &oldp );

	MANUAL_MAPPING_DATA data { 0 };
	data.pLoadLibraryA = LoadLibraryA;
	data.pGetProcAddress = GetProcAddress;
#ifdef _WIN64
	data.pRtlAddFunctionTable = ( f_RtlAddFunctionTable ) RtlAddFunctionTable;
#else 
	SEHExceptionSupport = false;
#endif
	data.pbase = pTargetBase;
	data.fdwReasonParam = fdwReason;
	data.reservedParam = lpReserved;
	data.SEHSupport = SEHExceptionSupport;

	//File header
	if ( !WriteProcessMemory( hProc , pTargetBase , pSrcData , 0x1000 , nullptr ) ) { //only first 0x1000 bytes for the header
		ILog( xorstr_( "Can't write file header 0x%X\n" ) , GetLastError( ) );
		VirtualFreeEx( hProc , pTargetBase , 0 , MEM_RELEASE );
		return false;
	}

	IMAGE_SECTION_HEADER * pSectionHeader = IMAGE_FIRST_SECTION( pOldNtHeader );
	for ( UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i , ++pSectionHeader ) {
		if ( pSectionHeader->SizeOfRawData ) {
			if ( !WriteProcessMemory( hProc , pTargetBase + pSectionHeader->VirtualAddress , pSrcData + pSectionHeader->PointerToRawData , pSectionHeader->SizeOfRawData , nullptr ) ) {
				ILog( xorstr_( "Can't map sections: 0x%x\n" ) , GetLastError( ) );
				VirtualFreeEx( hProc , pTargetBase , 0 , MEM_RELEASE );
				return false;
			}
		}
	}

	//Mapping params
	BYTE * MappingDataAlloc = reinterpret_cast< BYTE * >( VirtualAllocEx( hProc , nullptr , sizeof( MANUAL_MAPPING_DATA ) , MEM_COMMIT | MEM_RESERVE , PAGE_READWRITE ) );
	if ( !MappingDataAlloc ) {
		ILog( xorstr_( "Target process mapping allocation failed (ex) 0x%X\n" ) , GetLastError( ) );
		VirtualFreeEx( hProc , pTargetBase , 0 , MEM_RELEASE );
		return false;
	}

	if ( !WriteProcessMemory( hProc , MappingDataAlloc , &data , sizeof( MANUAL_MAPPING_DATA ) , nullptr ) ) {
		ILog( xorstr_( "Can't write mapping 0x%X\n" ) , GetLastError( ) );
		VirtualFreeEx( hProc , pTargetBase , 0 , MEM_RELEASE );
		VirtualFreeEx( hProc , MappingDataAlloc , 0 , MEM_RELEASE );
		return false;
	}

	//Shell code
	void * pShellcode = VirtualAllocEx( hProc , nullptr , 0x1000 , MEM_COMMIT | MEM_RESERVE , PAGE_EXECUTE_READWRITE );
	if ( !pShellcode ) {
		ILog( xorstr_( "Memory shellcode allocation failed (ex) 0x%X\n" ) , GetLastError( ) );
		VirtualFreeEx( hProc , pTargetBase , 0 , MEM_RELEASE );
		VirtualFreeEx( hProc , MappingDataAlloc , 0 , MEM_RELEASE );
		return false;
	}

	if ( !WriteProcessMemory( hProc , pShellcode , Shellcode , 0x1000 , nullptr ) ) {
		ILog( xorstr_( "Can't write shellcode 0x%X\n" ) , GetLastError( ) );
		VirtualFreeEx( hProc , pTargetBase , 0 , MEM_RELEASE );
		VirtualFreeEx( hProc , MappingDataAlloc , 0 , MEM_RELEASE );
		VirtualFreeEx( hProc , pShellcode , 0 , MEM_RELEASE );
		return false;
	}


#ifdef _DEBUG
	ILog( xorstr_( "Mapped DLL at %p\n" , pTargetBase );
	ILog( xorstr_( "Mapping info at %p\n" , MappingDataAlloc );
	ILog( xorstr_( "Shell code at %p\n" , pShellcode );

	ILog( xorstr_( "Data allocated\n" );

	ILog( xorstr_( "My shellcode pointer %p\n" , Shellcode );
	ILog( xorstr_( "Target point %p\n" , pShellcode );
#endif

	HANDLE hThread = CreateRemoteThread( hProc , nullptr , 0 , reinterpret_cast< LPTHREAD_START_ROUTINE >( pShellcode ) , MappingDataAlloc , 0 , nullptr );
	if ( !hThread ) {
		ILog( xorstr_( "Thread creation failed 0x%X\n" ) , GetLastError( ) );
		VirtualFreeEx( hProc , pTargetBase , 0 , MEM_RELEASE );
		VirtualFreeEx( hProc , MappingDataAlloc , 0 , MEM_RELEASE );
		VirtualFreeEx( hProc , pShellcode , 0 , MEM_RELEASE );
		return false;
	}
	CloseHandle( hThread );

	//ILog( xorstr_("Thread created at: %p, waiting for return...\n", pShellcode);

	HINSTANCE hCheck = NULL;
	int times = 0;
	while ( !hCheck && times < 100) {
		if ( times == 99 ) {
			ILog( xorstr_( "Process timed out\n" ) );
			return false;
		}
		DWORD exitcode = 0;
		GetExitCodeProcess( hProc , &exitcode );
		if ( exitcode != STILL_ACTIVE ) {
			ILog( xorstr_( "Process crashed, exit code: %d\n" ) , exitcode );
			return false;
		}

		MANUAL_MAPPING_DATA data_checked { 0 };
		ReadProcessMemory( hProc , MappingDataAlloc , &data_checked , sizeof( data_checked ) , nullptr );
		hCheck = data_checked.hMod;

		if ( hCheck == ( HINSTANCE ) 0x404040 ) {
			ILog( xorstr_( "Wrong mapping ptr\n" ) );
			VirtualFreeEx( hProc , pTargetBase , 0 , MEM_RELEASE );
			VirtualFreeEx( hProc , MappingDataAlloc , 0 , MEM_RELEASE );
			VirtualFreeEx( hProc , pShellcode , 0 , MEM_RELEASE );
			return false;
		}
		else if ( hCheck == ( HINSTANCE ) 0x505050 ) {
			ILog( xorstr_( "WARNING: Exception support failed!\n" ) );
		}
		times++;
		Sleep( 100 );
	}

	BYTE * emptyBuffer = ( BYTE * ) malloc( 1024 * 1024 * 20 );
	if ( emptyBuffer == nullptr ) {
		ILog( xorstr_( "Unable to allocate memory\n" ) );
		return false;
	}
	memset( emptyBuffer , 0 , 1024 * 1024 * 20 );



	//CLEAR PE HEAD
	if ( ClearHeader ) {
		if ( !WriteProcessMemory( hProc , pTargetBase , emptyBuffer , 0x1000 , nullptr ) ) {
			ILog( xorstr_( "WARNING!: Can't clear HEADER\n" ) );
		}
	}
	//END CLEAR PE HEAD


	if ( ClearNonNeededSections ) {
		pSectionHeader = IMAGE_FIRST_SECTION( pOldNtHeader );
		for ( UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i , ++pSectionHeader ) {
			if ( pSectionHeader->Misc.VirtualSize ) {
				if ( ( SEHExceptionSupport ? 0 : strcmp( ( char * ) pSectionHeader->Name , xorstr_(".pdata") ) == 0 ) ||
					strcmp( ( char * ) pSectionHeader->Name , xorstr_(".rsrc") ) == 0 ||
					strcmp( ( char * ) pSectionHeader->Name , xorstr_(".reloc") ) == 0 ) {
					//ILog( xorstr_("Processing %s removal\n", pSectionHeader->Name);
					if ( !WriteProcessMemory( hProc , pTargetBase + pSectionHeader->VirtualAddress , emptyBuffer , pSectionHeader->Misc.VirtualSize , nullptr ) ) {
						ILog( xorstr_( "Can't clear section %s: 0x%x\n" ) , pSectionHeader->Name , GetLastError( ) );
					}
				}
			}
		}
	}

	if ( AdjustProtections ) {
		pSectionHeader = IMAGE_FIRST_SECTION( pOldNtHeader );
		for ( UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i , ++pSectionHeader ) {
			if ( pSectionHeader->Misc.VirtualSize ) {
				DWORD old = 0;
				DWORD newP = PAGE_READONLY;

				if ( ( pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE ) > 0 ) {
					newP = PAGE_READWRITE;
				}
				else if ( ( pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE ) > 0 ) {
					newP = PAGE_EXECUTE_READ;
				}
				if ( VirtualProtectEx( hProc , pTargetBase + pSectionHeader->VirtualAddress , pSectionHeader->Misc.VirtualSize , newP , &old ) ) {
					//ILog( xorstr_("section %s set as %lX\n", (char*)pSectionHeader->Name, newP);
				}
				else {
					ILog( xorstr_( "FAIL: section %s not set as %lX\n" ) , ( char * ) pSectionHeader->Name , newP );
				}
			}
		}
		DWORD old = 0;
		VirtualProtectEx( hProc , pTargetBase , IMAGE_FIRST_SECTION( pOldNtHeader )->VirtualAddress , PAGE_READONLY , &old );
	}



	if ( !WriteProcessMemory( hProc , pShellcode , emptyBuffer , 0x1000 , nullptr ) ) {
		ILog( xorstr_( "WARNING: Can't clear shellcode\n" ) );
	}
	if ( !VirtualFreeEx( hProc , pShellcode , 0 , MEM_RELEASE ) ) {
		ILog( xorstr_( "WARNING: can't release shell code memory\n" ) );
	}
	if ( !VirtualFreeEx( hProc , MappingDataAlloc , 0 , MEM_RELEASE ) ) {
		ILog( xorstr_( "WARNING: can't release mapping data memory\n" ) );
	}


	return true;
}

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

#pragma runtime_checks( "", off )
#pragma optimize( "", off )
void __stdcall Shellcode( MANUAL_MAPPING_DATA * pData ) {
	if ( !pData ) {
		pData->hMod = ( HINSTANCE ) 0x404040;
		return;
	}

	BYTE * pBase = pData->pbase;
	auto * pOpt = &reinterpret_cast< IMAGE_NT_HEADERS * >( pBase + reinterpret_cast< IMAGE_DOS_HEADER * >( ( uintptr_t ) pBase )->e_lfanew )->OptionalHeader;

	auto _LoadLibraryA = pData->pLoadLibraryA;
	auto _GetProcAddress = pData->pGetProcAddress;
#ifdef _WIN64
	auto _RtlAddFunctionTable = pData->pRtlAddFunctionTable;
#endif
	auto _DllMain = reinterpret_cast< f_DLL_ENTRY_POINT >( pBase + pOpt->AddressOfEntryPoint );

	BYTE * LocationDelta = pBase - pOpt->ImageBase;
	if ( LocationDelta ) {
		if ( pOpt->DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].Size ) {
			auto * pRelocData = reinterpret_cast< IMAGE_BASE_RELOCATION * >( pBase + pOpt->DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].VirtualAddress );
			const auto * pRelocEnd = reinterpret_cast< IMAGE_BASE_RELOCATION * >( reinterpret_cast< uintptr_t >( pRelocData ) + pOpt->DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].Size );
			while ( pRelocData < pRelocEnd && pRelocData->SizeOfBlock ) {
				UINT AmountOfEntries = ( pRelocData->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION ) ) / sizeof( WORD );
				WORD * pRelativeInfo = reinterpret_cast< WORD * >( pRelocData + 1 );

				for ( UINT i = 0; i != AmountOfEntries; ++i , ++pRelativeInfo ) {
					if ( RELOC_FLAG( *pRelativeInfo ) ) {
						UINT_PTR * pPatch = reinterpret_cast< UINT_PTR * >( pBase + pRelocData->VirtualAddress + ( ( *pRelativeInfo ) & 0xFFF ) );
						*pPatch += reinterpret_cast< UINT_PTR >( LocationDelta );
					}
				}
				pRelocData = reinterpret_cast< IMAGE_BASE_RELOCATION * >( reinterpret_cast< BYTE * >( pRelocData ) + pRelocData->SizeOfBlock );
			}
		}
	}

	if ( pOpt->DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].Size ) {
		auto * pImportDescr = reinterpret_cast< IMAGE_IMPORT_DESCRIPTOR * >( pBase + pOpt->DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress );
		while ( pImportDescr->Name ) {
			char * szMod = reinterpret_cast< char * >( pBase + pImportDescr->Name );
			HINSTANCE hDll = _LoadLibraryA( szMod );

			ULONG_PTR * pThunkRef = reinterpret_cast< ULONG_PTR * >( pBase + pImportDescr->OriginalFirstThunk );
			ULONG_PTR * pFuncRef = reinterpret_cast< ULONG_PTR * >( pBase + pImportDescr->FirstThunk );

			if ( !pThunkRef )
				pThunkRef = pFuncRef;

			for ( ; *pThunkRef; ++pThunkRef , ++pFuncRef ) {
				if ( IMAGE_SNAP_BY_ORDINAL( *pThunkRef ) ) {
					*pFuncRef = ( ULONG_PTR ) _GetProcAddress( hDll , reinterpret_cast< char * >( *pThunkRef & 0xFFFF ) );
				}
				else {
					auto * pImport = reinterpret_cast< IMAGE_IMPORT_BY_NAME * >( pBase + ( *pThunkRef ) );
					*pFuncRef = ( ULONG_PTR ) _GetProcAddress( hDll , pImport->Name );
				}
			}
			++pImportDescr;
		}
	}

	if ( pOpt->DataDirectory[ IMAGE_DIRECTORY_ENTRY_TLS ].Size ) {
		auto * pTLS = reinterpret_cast< IMAGE_TLS_DIRECTORY * >( pBase + pOpt->DataDirectory[ IMAGE_DIRECTORY_ENTRY_TLS ].VirtualAddress );
		auto * pCallback = reinterpret_cast< PIMAGE_TLS_CALLBACK * >( pTLS->AddressOfCallBacks );
		for ( ; pCallback && *pCallback; ++pCallback )
			( *pCallback )( pBase , DLL_PROCESS_ATTACH , nullptr );
	}

	bool ExceptionSupportFailed = false;

#ifdef _WIN64

	if ( pData->SEHSupport ) {
		auto excep = pOpt->DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXCEPTION ];
		if ( excep.Size ) {
			if ( !_RtlAddFunctionTable(
				reinterpret_cast< IMAGE_RUNTIME_FUNCTION_ENTRY * >( pBase + excep.VirtualAddress ) ,
				excep.Size / sizeof( IMAGE_RUNTIME_FUNCTION_ENTRY ) , ( DWORD64 ) pBase ) ) {
				ExceptionSupportFailed = true;
			}
		}
	}

#endif

	_DllMain( pBase , pData->fdwReasonParam , pData->reservedParam );

	if ( ExceptionSupportFailed )
		pData->hMod = reinterpret_cast< HINSTANCE >( 0x505050 );
	else
		pData->hMod = reinterpret_cast< HINSTANCE >( pBase );
}

bool IsCorrectTargetArchitecture( HANDLE hProc ) {
	BOOL bTarget = FALSE;
	if ( !IsWow64Process( hProc , &bTarget ) ) {
		//printf( "Can't confirm target process architecture: 0x%X\n" , GetLastError( ) );
		return false;
	}

	BOOL bHost = FALSE;
	IsWow64Process( GetCurrentProcess( ) , &bHost );

	return ( bTarget == bHost );
}


int Injector::Inject( std::string DllPath , DWORD PID )
{
	TOKEN_PRIVILEGES priv = { 0 };
	HANDLE hToken = NULL;
	if ( OpenProcessToken( GetCurrentProcess( ) , TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY , &hToken ) ) {
		priv.PrivilegeCount = 1;
		priv.Privileges[ 0 ].Attributes = SE_PRIVILEGE_ENABLED;

		if ( LookupPrivilegeValue( NULL , SE_DEBUG_NAME , &priv.Privileges[ 0 ].Luid ) )
			AdjustTokenPrivileges( hToken , FALSE , &priv , 0 , NULL , NULL );

		CloseHandle( hToken );
	}

	HANDLE hProc = OpenProcess( PROCESS_ALL_ACCESS , FALSE , PID );
	if ( !hProc ) {
		DWORD Err = GetLastError( );
		//std::cout << ( "OpenProcess failed: 0x%X\n" , Err );
		//system("PAUSE");
		return -2;
	}

	if ( !IsCorrectTargetArchitecture( hProc ) ) {
		//std::cout << ( "Invalid Process Architecture.\n" );
		CloseHandle( hProc );
		//system("PAUSE");
		return -3;
	}

	if ( GetFileAttributes( DllPath.c_str( ) ) == INVALID_FILE_ATTRIBUTES ) {
		//std::cout << ( "Dll file doesn't exist\n" );
		CloseHandle( hProc );
		//system("PAUSE");
		return -4;
	}

	std::ifstream File( DllPath , std::ios::binary | std::ios::ate );

	if ( File.fail( ) ) {
		//std::cout << ( "Opening the file failed: %X\n" , ( DWORD ) File.rdstate( ) );
		File.close( );
		CloseHandle( hProc );
		//system("PAUSE");
		return -5;
	}

	auto FileSize = File.tellg( );
	if ( FileSize < 0x1000 ) {
		//std::cout << "Filesize invalid.\n";
		File.close( );
		CloseHandle( hProc );
		//system("PAUSE");
		return -6;
	}

	BYTE * pSrcData = new BYTE[ ( UINT_PTR ) FileSize ];
	if ( !pSrcData ) {
		//std::cout << ( "Can't allocate dll file.\n" );
		File.close( );
		CloseHandle( hProc );
		return -7;
	}

	File.seekg( 0 , std::ios::beg );
	File.read( ( char * ) ( pSrcData ) , FileSize );
	File.close( );

	//std::cout << "Mapping...\n";
	if ( !ManualMapDll( hProc , pSrcData , FileSize ) ) {
		delete[ ] pSrcData;
		CloseHandle( hProc );
		//std::cout << "Error while mapping.\n";
		return -8;
	}
	delete[ ] pSrcData;
	CloseHandle( hProc );
	return 1;
}

bool Injector::InjectBytes( std::vector<std::uint8_t> bytes , DWORD PID )
{
	TOKEN_PRIVILEGES priv = { 0 };
	HANDLE hToken = NULL;
	if ( OpenProcessToken( GetCurrentProcess( ) , TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY , &hToken ) ) {
		priv.PrivilegeCount = 1;
		priv.Privileges[ 0 ].Attributes = SE_PRIVILEGE_ENABLED;

		if ( LookupPrivilegeValue( NULL , SE_DEBUG_NAME , &priv.Privileges[ 0 ].Luid ) )
			AdjustTokenPrivileges( hToken , FALSE , &priv , 0 , NULL , NULL );

		CloseHandle( hToken );
	}

	HANDLE hProc = OpenProcess( PROCESS_ALL_ACCESS , FALSE , PID );
	if ( !hProc ) {
		DWORD Err = GetLastError( );
		//system("PAUSE");
		return false;
	}

	if ( !IsCorrectTargetArchitecture( hProc ) ) {
		CloseHandle( hProc );
		//system("PAUSE");
		return false;
	}
	//file.write((char*)bytes.data(), bytes.size());

	BYTE * pSrcData = new BYTE;
	pSrcData = bytes.data( );

	if ( !pSrcData )
	{
		CloseHandle( hProc );
		return false;
	}

	//std::cout << "Mapping...\n";
	if ( !ManualMapDll( hProc , pSrcData , sizeof( *pSrcData ) ) )
	{
		delete pSrcData;
		CloseHandle( hProc );
		//system("PAUSE");
		return false;
	}

	pSrcData = nullptr;
	delete pSrcData;

	CloseHandle( hProc );
	//std::cout << ("OK\n");
	return true;
}