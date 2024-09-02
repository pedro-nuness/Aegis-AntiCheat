#pragma once
#include <string>
#include <fstream>
#include <vector>


class File 
{
	std::string FilePath, FileName, FullPath = "";

	int _Lines = -1;
	bool _NeedLinesUpdate = true;

	std::vector<File> Copies;

public:

	File( std::string _filepath, std::string _filename );

	bool Delete( );
	bool Create( );
	bool IsEmpty( );
	bool Exists( );

	void Clear( );
	void EraseLine( int _line );
	void WriteOnLine( std::string _data , int _line );

	int GetNumLines( );

	bool Move( std::string _path );
	void Copy( std::string _path , std::string _name = "" );



	std::vector<File> GetCopies( );

	std::string Read( );
	std::string ReadLine( int _line );

	std::string GetFilePath( );
	std::string GetFileName( );
	std::string GetFullFilePath( );

	std::vector<std::string> ReadLines( );

	template<typename T>
	void Write( T _data , bool _BreakLine = true ) {
		std::ofstream _file( this->FullPath , std::ios::app );
		_file << _data;
		if ( _BreakLine )
			_file << "\n";
		_file.close( );
		_NeedLinesUpdate = true;
	}
};

