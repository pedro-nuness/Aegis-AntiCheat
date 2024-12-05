#include <iostream>
#include <winsock2.h>
#include <Windows.h>
#include <ShlObj.h>
#include <ShlObj_core.h>
#include <thread>
#include <ws2tcpip.h>
#include <fstream>

#include "externals/minhook/MinHook.h"

#pragma comment(lib, "ws2_32.lib")

// Ponteiros para as funções originais
typedef int( WINAPI * send_t )( SOCKET s , const char * buf , int len , int flags );
typedef int( WINAPI * recv_t )( SOCKET s , char * buf , int len , int flags );

send_t oSend = nullptr;
recv_t oRecv = nullptr;

// Defina o tipo da função original
typedef int ( WSAAPI * Connect_t )( SOCKET s , const struct sockaddr * name , int namelen );

// Ponteiro para a função original
Connect_t oConnect = nullptr;

bool CreateRegHooks( );

// Função hookada
int WSAAPI HookedConnect( SOCKET s , const struct sockaddr * name , int namelen )
{
	char ip[ INET6_ADDRSTRLEN ] = { 0 };

	// Verifique o tipo de socket (IPv4 ou IPv6) e converta para string
	if ( name->sa_family == AF_INET ) {
		sockaddr_in * addr = ( sockaddr_in * ) name;
		inet_ntop( AF_INET , &addr->sin_addr , ip , INET6_ADDRSTRLEN );
	}
	else if ( name->sa_family == AF_INET6 ) {
		sockaddr_in6 * addr = ( sockaddr_in6 * ) name;
		inet_ntop( AF_INET6 , &addr->sin6_addr , ip , INET6_ADDRSTRLEN );
	}

	std::cout << "[Hooked] connect called! IP: " << ip << std::endl;


	// Chame a função original
	return oConnect( s , name , namelen );
}
typedef BOOL( WINAPI * CreateProcessA_t )(
	LPCSTR lpApplicationName ,
	LPSTR lpCommandLine ,
	LPSECURITY_ATTRIBUTES lpProcessAttributes ,
	LPSECURITY_ATTRIBUTES lpThreadAttributes ,
	BOOL bInheritHandles ,
	DWORD dwCreationFlags ,
	LPVOID lpEnvironment ,
	LPCSTR lpCurrentDirectory ,
	LPSTARTUPINFOA lpStartupInfo ,
	LPPROCESS_INFORMATION lpProcessInformation
	);

typedef BOOL( WINAPI * CreateProcessW_t )(
	LPCWSTR lpApplicationName ,
	LPWSTR lpCommandLine ,
	LPSECURITY_ATTRIBUTES lpProcessAttributes ,
	LPSECURITY_ATTRIBUTES lpThreadAttributes ,
	BOOL bInheritHandles ,
	DWORD dwCreationFlags ,
	LPVOID lpEnvironment ,
	LPCWSTR lpCurrentDirectory ,
	LPSTARTUPINFOW lpStartupInfo ,
	LPPROCESS_INFORMATION lpProcessInformation
	);

typedef BOOL( WINAPI * CreateProcessInternalW_t )(
	HANDLE hToken ,
	LPCWSTR lpApplicationName ,
	LPWSTR lpCommandLine ,
	LPSECURITY_ATTRIBUTES lpProcessAttributes ,
	LPSECURITY_ATTRIBUTES lpThreadAttributes ,
	BOOL bInheritHandles ,
	DWORD dwCreationFlags ,
	LPVOID lpEnvironment ,
	LPCWSTR lpCurrentDirectory ,
	LPSTARTUPINFOW lpStartupInfo ,
	LPPROCESS_INFORMATION lpProcessInformation ,
	LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList
	);

// Ponteiros para armazenar as funções originais
CreateProcessA_t originalCreateProcessA = nullptr;
CreateProcessW_t originalCreateProcessW = nullptr;
CreateProcessInternalW_t originalCreateProcessInternalW = nullptr;

BOOL WINAPI Hooked_CreateProcessA(
	LPCSTR lpApplicationName ,
	LPSTR lpCommandLine ,
	LPSECURITY_ATTRIBUTES lpProcessAttributes ,
	LPSECURITY_ATTRIBUTES lpThreadAttributes ,
	BOOL bInheritHandles ,
	DWORD dwCreationFlags ,
	LPVOID lpEnvironment ,
	LPCSTR lpCurrentDirectory ,
	LPSTARTUPINFOA lpStartupInfo ,
	LPPROCESS_INFORMATION lpProcessInformation
)
{
	std::cout << lpCommandLine << std::endl;

	// Chame a função original
	if ( originalCreateProcessA != nullptr )
	{
		return originalCreateProcessA(
			lpApplicationName ,
			lpCommandLine ,
			lpProcessAttributes ,
			lpThreadAttributes ,
			bInheritHandles ,
			dwCreationFlags ,
			lpEnvironment ,
			lpCurrentDirectory ,
			lpStartupInfo ,
			lpProcessInformation
		);
	}

	return FALSE;  // Retorne FALSE em caso de erro
}

BOOL WINAPI Hooked_CreateProcessW(
	LPCWSTR lpApplicationName ,
	LPWSTR lpCommandLine ,
	LPSECURITY_ATTRIBUTES lpProcessAttributes ,
	LPSECURITY_ATTRIBUTES lpThreadAttributes ,
	BOOL bInheritHandles ,
	DWORD dwCreationFlags ,
	LPVOID lpEnvironment ,
	LPCWSTR lpCurrentDirectory ,
	LPSTARTUPINFOW lpStartupInfo ,
	LPPROCESS_INFORMATION lpProcessInformation
)
{
	std::wcout << lpCommandLine << std::endl;


	// Chame a função original
	if ( originalCreateProcessW != nullptr )
	{
		return originalCreateProcessW(
			lpApplicationName ,
			lpCommandLine ,
			lpProcessAttributes ,
			lpThreadAttributes ,
			bInheritHandles ,
			dwCreationFlags ,
			lpEnvironment ,
			lpCurrentDirectory ,
			lpStartupInfo ,
			lpProcessInformation
		);
	}

	return FALSE;  // Retorne FALSE em caso de erro
}

BOOL WINAPI Hooked_CreateProcessInternalW(
	HANDLE hToken ,
	LPCWSTR lpApplicationName ,
	LPWSTR lpCommandLine ,
	LPSECURITY_ATTRIBUTES lpProcessAttributes ,
	LPSECURITY_ATTRIBUTES lpThreadAttributes ,
	BOOL bInheritHandles ,
	DWORD dwCreationFlags ,
	LPVOID lpEnvironment ,
	LPCWSTR lpCurrentDirectory ,
	LPSTARTUPINFOW lpStartupInfo ,
	LPPROCESS_INFORMATION lpProcessInformation ,
	LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList
)
{
	// Modifique os parâmetros ou registre informações antes de chamar a função original
	//MessageBoxW( NULL , L"CreateProcessInternalW chamada" , L"Interceptado" , MB_OK );
	std::wcout << lpCommandLine << std::endl;


	// Chame a função original
	if ( originalCreateProcessInternalW != nullptr )
	{
		return originalCreateProcessInternalW(
			hToken ,
			lpApplicationName ,
			lpCommandLine ,
			lpProcessAttributes ,
			lpThreadAttributes ,
			bInheritHandles ,
			dwCreationFlags ,
			lpEnvironment ,
			lpCurrentDirectory ,
			lpStartupInfo ,
			lpProcessInformation ,
			lpAttributeList
		);
	}

	return FALSE;  // Retorne FALSE em caso de erro
}


#include <mutex>

// Mutex para evitar condições de corrida
std::mutex fileMutex;

// Função para registrar dados enviados
void LogDataToFile( const std::string & fileName , const std::string & data ) {
	std::lock_guard<std::mutex> lock( fileMutex );
	std::ofstream file( "c:\\" +fileName , std::ios::app ); // Abre o arquivo em modo de append
	if ( file.is_open( ) ) {
		file << data << "\n"; // Escreve os dados no arquivo
		file.close( );
	}
}

// Função `send` personalizada
int WINAPI HookedSend( SOCKET s , const char * buf , int len , int flags ) {
	// Loga os dados enviados no arquivo send.dump
	LogDataToFile( "send.dump" , std::string( buf , len ) );
	return oSend( s , buf , len , flags ); // Chama a função original
}

// Função `recv` personalizada
int WINAPI HookedRecv( SOCKET s , char * buf , int len , int flags ) {
	int result = oRecv( s , buf , len , flags ); // Chama a função original
	if ( result > 0 ) {
		// Loga os dados recebidos no arquivo recv.dump
		LogDataToFile( "recv.dump" , std::string( buf , result ) );
	}
	return result;
}


LRESULT CALLBACK WindowProcedure( HWND hwnd , UINT msg , WPARAM wp , LPARAM lp )
{
	switch ( msg )
	{
	case WM_DESTROY:
		PostQuitMessage( 0 );
		break;
	default:
		return DefWindowProc( hwnd , msg , wp , lp );
	}
	return 0;
}

// Definição do tipo da função original
typedef BOOL( WINAPI * FreeConsole_t )( VOID );

// Ponteiro para a função original
FreeConsole_t oFreeConsole = nullptr;
// Função hook para FreeConsole
BOOL WINAPI HookedFreeConsole( ) {
	std::cout << "[Hooked] FreeConsole chamada." << std::endl;
	// Chama a função original
	return FALSE;
	return oFreeConsole( );
}


bool InitHooks( ) {
	//std::cout xorstr_("[-] MainThread Started\n");
	if ( MH_Initialize( ) != MH_OK ) {
		return false;
	}
	//std::cout xorstr_("[HOOKLIB] Initialized\n");



	if ( MH_CreateHookApi( L"ws2_32.dll" , "send" , &HookedSend , reinterpret_cast< LPVOID * >( &oSend ) ) != MH_OK ) {
		std::cerr << "Falha ao criar hook para send" << std::endl;
		return false;
	}

	// Hook para a função `recv`
	if ( MH_CreateHookApi( L"ws2_32.dll" , "recv" , &HookedRecv , reinterpret_cast< LPVOID * >( &oRecv ) ) != MH_OK ) {
		std::cerr << "Falha ao criar hook para recv" << std::endl;
		return false;
	}

	// Crie um hook para a função connect
	if ( MH_CreateHookApi(
		L"ws2_32.dll" ,     // Nome da DLL
		"connect" ,         // Nome da função a ser hookada
		&HookedConnect ,    // Função substituta
		reinterpret_cast< LPVOID * >( &oConnect ) ) != MH_OK )
	{
		std::cerr << "Failed to create hook for connect!" << std::endl;
		return false;
	}

	if ( MH_CreateHookApi( L"kernel32.dll" , "FreeConsole" , &HookedFreeConsole , reinterpret_cast< LPVOID * >( &oFreeConsole ) ) != MH_OK ) {
		std::cerr << "Falha ao criar hook para FreeConsole!" << std::endl;
		return false;
	}
	
	// Cria o hook para CreateProcessA
	if ( MH_CreateHookApi( L"kernel32.dll" , "CreateProcessA" , &Hooked_CreateProcessA , reinterpret_cast< void ** >( &originalCreateProcessA ) ) != MH_OK )
	{
		MessageBoxW( NULL , L"Falha ao criar o hook para CreateProcessA" , L"Erro" , MB_OK );
		return false;
	}

	// Cria o hook para CreateProcessW
	if ( MH_CreateHookApi( L"kernel32.dll" , "CreateProcessW" , &Hooked_CreateProcessW , reinterpret_cast< void ** >( &originalCreateProcessW ) ) != MH_OK )
	{
		MessageBoxW( NULL , L"Falha ao criar o hook para CreateProcessW" , L"Erro" , MB_OK );
		return false;
	}

	// Cria o hook para CreateProcessInternalW
	if ( MH_CreateHookApi( L"kernel32.dll" , "CreateProcessInternalW" , &Hooked_CreateProcessInternalW , reinterpret_cast< void ** >( &originalCreateProcessInternalW ) ) != MH_OK )
	{
		MessageBoxW( NULL , L"Falha ao criar o hook para CreateProcessInternalW" , L"Erro" , MB_OK );
		return false;
	}



	CreateRegHooks( );


	// Ative o hook
	if ( MH_EnableHook( MH_ALL_HOOKS ) != MH_OK ) {
		std::cerr << "Failed to enable hooks!" << std::endl;
		return 1;
	}


	MH_EnableHook( MH_ALL_HOOKS );

	return true;
}

bool SaveFirstFunctionBytes( const std::string & moduleName , const std::string & functionName , const std::string & outputFileName , size_t byteCount ) {
	// Obter o handle do módulo
	HMODULE hModule = GetModuleHandleA( moduleName.c_str( ) );
	if ( !hModule ) {
		std::cerr << "Erro: Não foi possível encontrar o módulo: " << moduleName << std::endl;
		return false;
	}

	// Obter o endereço da função
	FARPROC funcAddress = GetProcAddress( hModule , functionName.c_str( ) );
	if ( !funcAddress ) {
		std::cerr << "Erro: Não foi possível encontrar a função: " << functionName << std::endl;
		return false;
	}

	// Salvar os primeiros X bytes da função
	BYTE * start = reinterpret_cast< BYTE * >( funcAddress );

	std::ofstream outFile( outputFileName );
	if ( !outFile.is_open( ) ) {
		std::cerr << "Erro: Não foi possível abrir o arquivo: " << outputFileName << std::endl;
		return false;
	}

	outFile << "unsigned char functionBytes[] = {";
	for ( size_t i = 0; i < byteCount; ++i ) {
		outFile << "0x" << std::hex << static_cast< int >( start[ i ] );
		if ( i < byteCount - 1 ) outFile << ", "; // Adiciona vírgula entre os bytes
	}
	outFile << "};" << std::endl;

	outFile.close( );
	return true;
}


DWORD WINAPI main( PVOID base )
{
	AllocConsole( );

	if ( !freopen( ( "CONOUT$" ) , ( "w" ) , stdout ) )
	{
		FreeConsole( );
		return EXIT_SUCCESS;
	}

	SaveFirstFunctionBytes( "ws2_32.dll" , "send" , "send_dump.bin" , 16 );
	SaveFirstFunctionBytes( "ws2_32.dll" , "recv" , "recv_dump.bin" , 16 );



	//std::cout << ( "[+] DLL Sucessfully attached at " ) << base << ( "\n" );

	//if(!InitHooks() )
	//	std::cout << ( "[!] failed to init hooks " ) << base << ( "\n" );

	//// Registrando a classe da janela
	//const char CLASS_NAME[ ] = "Sample Window Class";

	//WNDCLASS wc = { };
	//wc.lpfnWndProc = WindowProcedure;  // Função de callback
	//wc.hInstance = GetModuleHandle( nullptr );
	//wc.lpszClassName = CLASS_NAME;

	//RegisterClass( &wc );

	// // Criando a janela com os estilos WS_EX_LAYERED e WS_EX_TRANSPARENT
	//HWND hwnd = CreateWindowEx(
	//	WS_EX_LAYERED | WS_EX_TRANSPARENT , // Adicionando a flag de transparência e permitindo que o mouse passe
	//	CLASS_NAME ,
	//	"Janela Transparente e com Mouse Passando" ,
	//	WS_OVERLAPPEDWINDOW ,
	//	CW_USEDEFAULT , CW_USEDEFAULT , 500 , 400 ,
	//	nullptr , nullptr , wc.hInstance , nullptr
	//);

	//if ( hwnd == nullptr )
	//{
	//	return 0;
	//}

	//ShowWindow( hwnd , SW_SHOW );
	//UpdateWindow( hwnd );

	//// Loop de mensagens
	//MSG msg = { };
	//while ( GetMessage( &msg , nullptr , 0 , 0 ) )
	//{
	//	TranslateMessage( &msg );
	//	DispatchMessage( &msg );
	//}



	//while ( true ) {
	//	std::cout << "Hello from cheat: " << GetCurrentThreadId( ) << std::endl;
	//	std::this_thread::sleep_for( std::chrono::seconds( 1 ) );
	//}

	FreeConsole( );
	return EXIT_SUCCESS;
}

BOOL WINAPI DllMain( HMODULE hModule , DWORD dwReason , LPVOID lpReserved )
{
	switch ( dwReason ) {
	case DLL_PROCESS_ATTACH:
		CreateThread( nullptr , 0 , main , hModule , 0 , nullptr );
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}