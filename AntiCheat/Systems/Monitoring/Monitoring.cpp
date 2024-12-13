#include "Monitoring.h"


#include <string>
#include <iostream>
#include <thread>


#include "../LogSystem/File/File.h"
#include "../Utils/xorstr.h"
#include "../Utils/utils.h"
#include "../Utils/StringCrypt/StringCrypt.h"



HBITMAP Monitoring::ByteArrayToBitmap( const std::vector<BYTE> & bitmapData , int width , int height )
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

void Monitoring::SaveBitmapToFile( HBITMAP hBitmap , const std::string & filePath )
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


HBITMAP Monitoring::CaptureScreenBitmap( )
{
	HDC hDC = GetDC( NULL );
	HDC hMemDC = CreateCompatibleDC( hDC );

	INT x = GetSystemMetrics( SM_XVIRTUALSCREEN );
	INT y = GetSystemMetrics( SM_YVIRTUALSCREEN );
	INT lWidth = min( GetSystemMetrics( SM_CXVIRTUALSCREEN ) , 1920 );
	INT lHeight = min( GetSystemMetrics( SM_CYVIRTUALSCREEN ) , 1080 );

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

std::vector<BYTE> Monitoring::BitmapToByteArray( HBITMAP hBitmap )
{
	BITMAP bitmap;
	GetObject( hBitmap , sizeof( BITMAP ) , &bitmap );

	int dataSize = bitmap.bmWidthBytes * bitmap.bmHeight;
	std::vector<BYTE> bitmapData( dataSize );

	HDC hDC = GetDC( NULL );
	HDC hMemDC = CreateCompatibleDC( hDC );

	BITMAPINFOHEADER biHeader = {};
	biHeader.biSize = sizeof( BITMAPINFOHEADER );
	biHeader.biWidth = bitmap.bmWidth;
	biHeader.biHeight = bitmap.bmHeight;
	biHeader.biPlanes = 1;
	biHeader.biBitCount = 24;
	biHeader.biCompression = BI_RGB;

	GetDIBits( hMemDC , hBitmap , 0 , bitmap.bmHeight , bitmapData.data( ) , ( BITMAPINFO * ) &biHeader , DIB_RGB_COLORS );

	DeleteDC( hMemDC );
	ReleaseDC( NULL , hDC );

	return bitmapData;
}
std::vector<BYTE> Monitoring::CompressBitmapByteArray( const std::vector<BYTE> & bitmapByteArray ) {
	std::vector<BYTE> compressedArray;
	size_t i = 0;

	while ( i < bitmapByteArray.size( ) ) {
		BYTE current = bitmapByteArray[ i ];
		size_t count = 1;

		// Contar repetições consecutivas do byte atual
		while ( i + count < bitmapByteArray.size( ) && bitmapByteArray[ i + count ] == current && count < 255 ) {
			++count;
		}

		if ( count > 3 ) {
			// Sequência longa, adicionar sequência comprimida
			compressedArray.push_back( 0xFF ); // Flag para sequência
			compressedArray.push_back( current );
			compressedArray.push_back( static_cast< BYTE >( count ) );
		}
		else {
			// Adicionar bytes únicos como bloco
			size_t start = i;
			size_t blockLength = 0;
			while ( i < bitmapByteArray.size( ) && ( blockLength < 255 ) &&
				( i + 1 == bitmapByteArray.size( ) || bitmapByteArray[ i ] != bitmapByteArray[ i + 1 ] ) ) {
				++i;
				++blockLength;
			}
			compressedArray.push_back( static_cast< BYTE >( blockLength ) ); // Comprimento do bloco
			compressedArray.insert( compressedArray.end( ) , bitmapByteArray.begin( ) + start , bitmapByteArray.begin( ) + start + blockLength );
		}

		i += count;
	}

	return compressedArray;
}

std::vector<BYTE> Monitoring::DecompressBitmapByteArray( const std::vector<BYTE> & compressedArray ) {
	std::vector<BYTE> decompressedArray;
	size_t i = 0;

	while ( i < compressedArray.size( ) ) {
		BYTE flag = compressedArray[ i ];

		if ( flag == 0xFF ) {
			// Sequência comprimida
			BYTE value = compressedArray[ i + 1 ];
			BYTE count = compressedArray[ i + 2 ];
			decompressedArray.insert( decompressedArray.end( ) , count , value );
			i += 3;
		}
		else {
			// Bloco de bytes únicos
			size_t blockLength = static_cast< size_t >( flag );
			decompressedArray.insert( decompressedArray.end( ) , compressedArray.begin( ) + i + 1 , compressedArray.begin( ) + i + 1 + blockLength );
			i += 1 + blockLength;
		}
	}

	return decompressedArray;
}