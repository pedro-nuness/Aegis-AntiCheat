#include "File.h"
#include <iostream>
#include <filesystem>

File::File( std::string _filepath , std::string _filename )
{
	this->FilePath = _filepath;
	this->FileName = _filename;
	this->FullPath = _filepath + _filename;
}

bool File::Delete( ) {
	if ( !Exists( ) )
		return false;

	return std::filesystem::remove( this->FullPath.c_str( ) );
}

bool File::Create( ) {
	std::ofstream  _file( this->FullPath );
	_file.open( this->FullPath );
	return Exists( );
}


int File::GetNumLines( ) {

	if ( _NeedLinesUpdate ) {
		int CountLines = 0;

		std::fstream _file( this->FullPath );
		if ( _file.is_open( ) )
		{
			std::string str;
			while ( std::getline( _file , str ) )
			{
				CountLines++;
			}
		}
		_NeedLinesUpdate = false;
		_Lines = CountLines;
		_file.close( );
		return CountLines;
	}
	else {
		return this->_Lines;
	}

}


std::string File::Read( ) {
	std::string _data = "";

	std::fstream _file( this->FullPath );
	if ( _file.is_open( ) )
	{
		std::string str;
		while ( std::getline( _file , str ) ) {
			_data += str;
			_data += "\n";
		}
	}

	_file.close( );

	return _data;
}

std::string File::ReadLine( int _Line )
{
	std::string _data = "";
	std::fstream _file( this->FullPath );
	if ( _file.is_open( ) ) {
		std::string str;
		for ( int i = 0; i < _Line; i++ ) {
			std::getline( _file , str );
		}
		_data += str;
		_data.push_back( '\n' );
	}
	_file.close( );
	return _data;
}

std::vector<std::string> File::ReadLines( )
{
	std::vector<std::string> _data;
	std::fstream _file( this->FullPath );
	if ( _file.is_open( ) ) {
		std::string str;
		while ( std::getline( _file , str ) ) {
			_data.push_back( str );
		}
	}
	_file.close( );
	return _data;
}


bool File::IsEmpty( ) {
	std::ifstream _file( this->FullPath );
	if ( _file.is_open( ) ) {
		_file.seekg( 0 , std::ios::end );
		std::streampos _size = _file.tellg( );
		_file.close( );
		return( bool ) !_size;
	}
	return false;
}

void File::Clear( ) {
	std::fstream _file( this->FullPath , std::ios::out | std::ios::trunc );
	_file.close( );
	_NeedLinesUpdate = true;
}

void File::EraseLine( int _line )
{
	std::vector<std::string> _data = ReadLines( );
	if ( _line <= _data.size( ) ) {
		_data.erase( _data.begin( ) + _line );
		Clear( );
		for ( auto line : _data )
		{
			Write( line );
		}
	}
}

void File::WriteOnLine( std::string _data , int _line ) {
	auto _rdata = ReadLines( );
	if ( _line <= _rdata.size( ) && _line ) {
		_rdata[ _line ] = _data;
		Clear( );
		for ( auto data : _rdata ) {
			Write( data );
		}
	}
	_NeedLinesUpdate = true;
}

bool File::Exists( ) {
	return std::filesystem::exists( GetFullFilePath( ) );
}

void File::Copy( std::string _path , std::string _name )
{
	auto _data = ReadLines( );
	File _newfile( _path , _name );

	if ( _newfile.Exists() )
		_newfile.Delete( );
	
	_newfile.Create( );
	for ( auto data : _data )
		_newfile.Write( data );

	Copies.emplace_back( _newfile );
}

std::vector<File> File::GetCopies( ) {
	return this->Copies;
}

bool File::Move( std::string _path )
{
	std::vector<std::string >_currentdata;

	if ( !IsEmpty( ) )
		_currentdata = ReadLines( );

	if ( !Exists( ) )
		return false;
	
	Delete( );
	{
		this->FilePath = _path;
		this->FullPath = this->FilePath + this->FileName;

		if ( Create( ) ) {

			if ( !_currentdata.empty( ) ) {
				for ( auto data : _currentdata )
					Write( data );
			}

			return true;
		}
		else {
			std::cout << "[FS]: Failed creating file!\n";
			return false;
		}
	}
}


std::string File::GetFilePath( ) {
	return this->FilePath;
}

std::string File::GetFileName( ) {
	return this->FileName;
}

std::string File::GetFullFilePath( ) {
	return this->FullPath;
}

