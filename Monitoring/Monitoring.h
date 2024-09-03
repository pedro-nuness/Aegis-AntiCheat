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

	void Init( );
	void SendDetectionInfo( std::string info, bool Capture = true);
	void SendWarningInfo( std::string info, bool Capture = true );
	void SendInfo( std::string info , bool Capture = false );

};

