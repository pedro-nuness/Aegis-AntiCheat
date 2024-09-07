#pragma once
#include <Windows.h>
#include <string>
#include "../Utils/singleton.h"


struct BitmapData {
	BITMAPINFOHEADER biHeader;
	BYTE * pData;
	int dataSize;
};

class Monitoring : public CSingleton<Monitoring>
{
	BOOL SaveBitmapToFile( HBITMAP hBitmap , const char * wPath );
	HBITMAP CaptureScreenBitmap( );
	BitmapData ExtractBitmapMemory( HBITMAP hBitmap );
	HBITMAP ReconstructBitmap( const BitmapData & bitmapData );
	void SendBitMap( BitmapData Bitmap );
	void GenerateScreenShot( std::string FileName );

public:
	Monitoring( ) {

	}
	void SendInfo( std::string info , uint32_t Color = NULL , bool Capture = true );
};

