#pragma once
#include "../utils/singleton.h"
#include <vector>
#include <windows.h>
#include <string>


class image : public CSingleton<image>
{
public:
	HBITMAP ByteArrayToBitmap( const std::vector<BYTE> & bitmapData , int width , int height );
	void SaveBitmapToFile( HBITMAP hBitmap , const std::string & filePath );
	std::vector<BYTE> CompressBitmapByteArray(  std::vector<BYTE> & bitmapByteArray );
	std::vector<BYTE> DecompressBitmapByteArray(  std::vector<BYTE> & compressedArray );
};

