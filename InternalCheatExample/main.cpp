#include <iostream>
#include <winsock2.h>
#include <Windows.h>
#include <ShlObj.h>
#include <ShlObj_core.h>
#include <thread>
#include <minhook/MinHook.h>

#pragma comment(lib, "ws2_32.lib")

// Ponteiros para as funções originais
typedef int( WINAPI * send_t )( SOCKET s , const char * buf , int len , int flags );
typedef int( WINAPI * recv_t )( SOCKET s , char * buf , int len , int flags );

send_t oSend = nullptr;
recv_t oRecv = nullptr;

// Função `send` personalizada
int WINAPI HookedSend( SOCKET s , const char * buf , int len , int flags ) {
	std::cout << "[HookedSend] Enviando dados: " << std::string( buf , len ) << std::endl;
	return oSend( s , buf , len , flags ); // Chama a função original
}

// Função `recv` personalizada
int WINAPI HookedRecv( SOCKET s , char * buf , int len , int flags ) {
	int result = oRecv( s , buf , len , flags ); // Chama a função original
	if ( result > 0 ) {
		std::cout << "[HookedRecv] Recebendo dados: " << std::string( buf , result ) << std::endl;
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



bool InitHooks( ) {
	//std::cout xorstr_("[-] MainThread Started\n");
	if ( MH_Initialize( ) != MH_OK ) {
		return false;
	}
	//std::cout xorstr_("[HOOKLIB] Initialized\n");


	if ( MH_CreateHookApi( L"ws2_32.dll" , "send" , &HookedSend , reinterpret_cast< LPVOID * >( &oSend ) ) != MH_OK ) {
		std::cerr << "Falha ao criar hook para send" << std::endl;
	}

	// Hook para a função `recv`
	if ( MH_CreateHookApi( L"ws2_32.dll" , "recv" , &HookedRecv , reinterpret_cast< LPVOID * >( &oRecv ) ) != MH_OK ) {
		std::cerr << "Falha ao criar hook para recv" << std::endl;
	}

	MH_EnableHook( MH_ALL_HOOKS );

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

	std::cout << ( "[+] DLL Sucessfully attached at " ) << base << ( "\n" );

	if(!InitHooks() )
		std::cout << ( "[!] failed to init hooks " ) << base << ( "\n" );

	// Registrando a classe da janela
	const char CLASS_NAME[ ] = "Sample Window Class";

	WNDCLASS wc = { };
	wc.lpfnWndProc = WindowProcedure;  // Função de callback
	wc.hInstance = GetModuleHandle( nullptr );
	wc.lpszClassName = CLASS_NAME;

	RegisterClass( &wc );

	 // Criando a janela com os estilos WS_EX_LAYERED e WS_EX_TRANSPARENT
	HWND hwnd = CreateWindowEx(
		WS_EX_LAYERED | WS_EX_TRANSPARENT , // Adicionando a flag de transparência e permitindo que o mouse passe
		CLASS_NAME ,
		"Janela Transparente e com Mouse Passando" ,
		WS_OVERLAPPEDWINDOW ,
		CW_USEDEFAULT , CW_USEDEFAULT , 500 , 400 ,
		nullptr , nullptr , wc.hInstance , nullptr
	);

	if ( hwnd == nullptr )
	{
		return 0;
	}

	ShowWindow( hwnd , SW_SHOW );
	UpdateWindow( hwnd );

	// Loop de mensagens
	MSG msg = { };
	while ( GetMessage( &msg , nullptr , 0 , 0 ) )
	{
		TranslateMessage( &msg );
		DispatchMessage( &msg );
	}



	while ( true ) {
		std::cout << "Hello from cheat: " << GetCurrentThreadId( ) << std::endl;
		std::this_thread::sleep_for( std::chrono::seconds( 1 ) );
	}

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