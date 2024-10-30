#include "image.h"
#include <fstream>

HBITMAP image::ByteArrayToBitmap( const std::vector<BYTE> & bitmapData , int width , int height )
{
	int dataSize = width * height * 3; // Assuming 24-bit (3 bytes per pixel)

	HDC hDC = GetDC( NULL );
	BITMAPINFOHEADER biHeader = {};
	biHeader.biSize = sizeof( BITMAPINFOHEADER );
	biHeader.biWidth = width;
	biHeader.biHeight = height;
	biHeader.biPlanes = 1;
	biHeader.biBitCount = 24;
	biHeader.biCompression = BI_RGB;

	BITMAPINFO bInfo = {};
	bInfo.bmiHeader = biHeader;

	BYTE * pBits = NULL;
	HBITMAP hBitmap = CreateDIBSection( hDC , &bInfo , DIB_RGB_COLORS , ( VOID ** ) &pBits , NULL , 0 );

	if ( hBitmap && pBits )
	{
		memcpy( pBits , bitmapData.data( ) , dataSize );
	}

	ReleaseDC( NULL , hDC );
	return hBitmap;
}

void image::SaveBitmapToFile( HBITMAP hBitmap , const std::string & filePath )
{
	BITMAP bitmap;
	GetObject( hBitmap , sizeof( BITMAP ) , &bitmap );

	BITMAPFILEHEADER bmfHeader = {};
	BITMAPINFOHEADER biHeader = {};

	biHeader.biSize = sizeof( BITMAPINFOHEADER );
	biHeader.biWidth = bitmap.bmWidth;
	biHeader.biHeight = bitmap.bmHeight;
	biHeader.biPlanes = 1;
	biHeader.biBitCount = 24;
	biHeader.biCompression = BI_RGB;
	biHeader.biSizeImage = bitmap.bmWidthBytes * bitmap.bmHeight;

	DWORD dwBmpSize = bitmap.bmWidthBytes * bitmap.bmHeight;
	std::vector<BYTE> bitmapData( dwBmpSize );

	HDC hDC = GetDC( NULL );
	HDC hMemDC = CreateCompatibleDC( hDC );
	GetDIBits( hMemDC , hBitmap , 0 , bitmap.bmHeight , bitmapData.data( ) , ( BITMAPINFO * ) &biHeader , DIB_RGB_COLORS );

	DeleteDC( hMemDC );
	ReleaseDC( NULL , hDC );

	bmfHeader.bfOffBits = sizeof( BITMAPFILEHEADER ) + sizeof( BITMAPINFOHEADER );
	bmfHeader.bfSize = bmfHeader.bfOffBits + biHeader.biSizeImage;
	bmfHeader.bfType = 0x4D42; // "BM"

	std::ofstream file( filePath , std::ios::out | std::ios::binary );
	if ( file )
	{
		file.write( reinterpret_cast< const char * >( &bmfHeader ) , sizeof( BITMAPFILEHEADER ) );
		file.write( reinterpret_cast< const char * >( &biHeader ) , sizeof( BITMAPINFOHEADER ) );
		file.write( reinterpret_cast< const char * >( bitmapData.data( ) ) , dwBmpSize );
		file.close( );
	}
}