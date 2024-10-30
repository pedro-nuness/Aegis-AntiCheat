#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include "../Utils/singleton.h"


struct BitmapData {
	BITMAPINFOHEADER biHeader;
	BYTE * pData;
	int dataSize;
};

class Monitoring : public CSingleton<Monitoring>
{
	
public:
	Monitoring( ) {

	}

	void SaveBitmapToFile( HBITMAP hBitmap , const std::string & filePath );
	HBITMAP ByteArrayToBitmap( const std::vector<BYTE> & bitmapData , int width , int height );
	HBITMAP CaptureScreenBitmap( );
	std::vector<BYTE> BitmapToByteArray( HBITMAP hBitmap );
};

