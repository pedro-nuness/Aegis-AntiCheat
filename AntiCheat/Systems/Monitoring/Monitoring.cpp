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

std::vector<int> Monitoring::CompressToIntermediate( std::vector<BYTE> & bitmapByteArray ) {
	std::vector<int> compressedArray;
	size_t i = 0;

	while ( i < bitmapByteArray.size( ) ) {
		size_t maxPatternLength = 4;  // Limite para o comprimento do padrão
		size_t patternLength = 1;
		size_t repetitions = 1;

		// Tentar encontrar o padrão mais longo que se repete
		for ( size_t len = 1; len <= maxPatternLength; ++len ) {
			if ( i + len * 2 > bitmapByteArray.size( ) ) break;

			bool match = true;
			for ( size_t k = 0; k < len; ++k ) {
				if ( bitmapByteArray[ i + k ] != bitmapByteArray[ i + len + k ] ) {
					match = false;
					break;
				}
			}

			if ( match ) {
				patternLength = len;
				repetitions = 2;

				// Contar repetições do padrão
				while ( i + patternLength * ( repetitions + 1 ) <= bitmapByteArray.size( ) &&
					std::equal( bitmapByteArray.begin( ) + i ,
						bitmapByteArray.begin( ) + i + patternLength ,
						bitmapByteArray.begin( ) + i + patternLength * repetitions ) ) {
					++repetitions;
				}
				break;
			}
		}

		if ( repetitions > 1 ) {
			// Calcular o tamanho da compressão em formato de string
			int compressedSize = std::to_string( -2 ).length( ) + 1 // -2,
				+ std::to_string( patternLength ).length( ) + 1 // patternLength,
				+ std::to_string( repetitions ).length( ) + 1 // repetitions,
				+ patternLength * std::to_string( bitmapByteArray[ i ] ).length( ); // padrão

			// Calcular o tamanho da sequência original não comprimida
			int originalSize = repetitions * patternLength * 2 + ( repetitions - 1 ); // Ex: 23,23 (5 caracteres)

			// Comparar os tamanhos e decidir se vale a pena comprimir
			if ( compressedSize < originalSize ) {
				// Codificar sequência repetitiva como padrão
				compressedArray.push_back( -2 );                      // Flag de padrão
				compressedArray.push_back( static_cast< int >( patternLength ) );
				compressedArray.push_back( static_cast< int >( repetitions ) );
				for ( size_t j = 0; j < patternLength; ++j ) {
					compressedArray.push_back( static_cast< int >( bitmapByteArray[ i + j ] ) );
				}
				i += patternLength * repetitions;
			}
			else {
				// Caso não compense, armazenar os bytes repetidos de forma simples
				for ( size_t rep = 0; rep < repetitions; ++rep ) {
					compressedArray.push_back( static_cast< int >( bitmapByteArray[ i + rep ] ) );
				}
				i += repetitions;
			}
		}
		else {
			// Processar bytes únicos ou pequenas repetições
			BYTE current = bitmapByteArray[ i ];
			size_t count = 1;

			while ( i + count < bitmapByteArray.size( ) && bitmapByteArray[ i + count ] == current && count < 255 ) {
				++count;
			}

			if ( count > 3 ) {
				compressedArray.push_back( -1 );  // Flag de repetição simples
				compressedArray.push_back( static_cast< int >( current ) );
				compressedArray.push_back( static_cast< int >( count ) );
			}
			else {
				for ( size_t j = 0; j < count; ++j ) {
					compressedArray.push_back( static_cast< int >( current ) );
				}
			}
			i += count;
		}
	}

	return compressedArray;
}




std::vector<BYTE> Monitoring::DecompressFromIntermediate( std::vector<int> & compressedArray ) {
	std::vector<BYTE> decompressedArray;

	size_t i = 0;
	while ( i < compressedArray.size( ) ) {
		if ( compressedArray[ i ] == -2 ) {
			// Decodificar sequência de padrões
			int patternLength = compressedArray[ i + 1 ];
			int repetitions = compressedArray[ i + 2 ];

			for ( int rep = 0; rep < repetitions; ++rep ) {
				for ( int j = 0; j < patternLength; ++j ) {
					decompressedArray.push_back( static_cast< BYTE >( compressedArray[ i + 3 + j ] ) );
				}
			}
			i += 3 + patternLength;
		}
		else if ( compressedArray[ i ] == -1 ) {
			// Decodificar repetição simples
			BYTE value = static_cast< BYTE >( compressedArray[ i + 1 ] );
			int count = compressedArray[ i + 2 ];
			decompressedArray.insert( decompressedArray.end( ) , count , value );
			i += 3;
		}
		else {
			// Decodificar byte único
			decompressedArray.push_back( static_cast< BYTE >( compressedArray[ i ] ) );
			++i;
		}
	}

	return decompressedArray;
}
