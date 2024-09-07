#include <fstream>
#include "StringCrypt.h"
#include "../utils.h"
#include "../crypt_str.h"
#include "../../Memory/memory.h"
#include "../SHA1/sha1.h"


void StringCrypt::Init( ) {
	CryptedString cStr;
	cStr.Hash = crypt_str("d81df4fc01e3651581242a35aa11a56a67162563");
	cStr.EncryptedString = {
		{803, 69}, {623, 5}, {4520, -52}, {2595, 77}, {134, -19},
		{1553, 41}, {2129, -34}, {3133, -14}, {385, -29}, {3527, -94},
		{4608, 115}, {3754, -71}, {1706, -59}, {2244, -82}, {202, -102},
		{2658, -52}, {3132, 39}, {1452, -61}, {1208, -75}, {506, 53},
		{2711, -54}, {3987, -35}, {2160, -7}, {2246, 105}, {856, 31},
		{43, 58}, {3710, -28}, {1117, 11}, {256, 111}, {1775, -128},
		{4298, -95}, {1172, -33}, {955, 116}, {785, 32}, {4465, -63},
		{110, -54}, {1836, 4}, {3808, 83}, {3899, -9}, {684, -118},
		{2437, -81}, {2182, -80}, {2205, -105}, {2868, -2}, {3270, 106},
		{2792, 77}, {3274, 109}, {2531, 82}, {1786, 58}, {2890, -22},
		{766, 50}, {4630, 34}, {1110, -39}, {1581, 23}, {1929, -66},
		{3159, 31}, {3356, 74}, {1928, -87}, {1469, 121}, {3991, -81},
		{2919, 5}, {356, -45}, {4897, 86}, {2846, 24}, {4337, 94},
		{1226, -119}, {2666, -58}, {3395, 45}, {3108, 82}, {4491, -28},
		{2072, 81}, {2449, -39}, {3481, -70}, {905, -27}, {3437, -34},
		{2609, 4}, {1884, -3}, {3429, -49}, {4934, 27}, {2020, 123},
		{4594, -121}, {4999, -62}, {4857, 113}, {3766, -76}, {1969, -66},
		{1966, -70}, {2644, -36}, {1875, 7}, {3173, -13}, {1419, -55},
		{2650, 8}, {1704, -56}, {1628, -44}, {2202, -84}, {3520, -93},
		{3813, 99}, {1312, 90}, {597, -6}, {1306, 71}, {470, 126},
		{4707, -46}, {2505, 126}, {2711, -33}, {384, -14}, {416, -105},
		{2182, -56}, {3640, -5}, {2276, 99}, {770, 54}, {1989, -125},
		{2313, 61}, {4964, -29}, {2086, 33}, {1065, 49}, {565, 12},
		{2925, 1}, {2788, -119}, {2466, -51}, {3868, 44}, {444, -102},
		{3599, 56}
	};

	Strings.emplace_back( cStr );
}

std::string StringCrypt::EncryptString( std::string str  ) {
	
	std::string Hash = Mem::Get( ).GenerateHash( str );
	CryptedString cStr;
	cStr.Hash = Hash;

	std::string Result;
	for ( int i = 0; i < str.size( ); i++ ) {
		int Num = Utils::Get( ).RandomNumber( 1 , 5000 );
		CryptedChar cChar;
		cChar._Key = Num;
		cChar.Letter = str[ i ] - cChar._Key;
		Result += ( str[i ] - cChar._Key );
		cStr.EncryptedString.emplace_back( cChar );
	}
	Strings.emplace_back( cStr );
	SaveEncryptedStringsToFile( crypt_str("crypt.txt") );
	return Result;
}

bool StringCrypt::CleanString( std::string * sPtr ) {
	std::fill( sPtr->begin( ) , sPtr->end( ) , 0 );
	delete sPtr;
	return true;
}

std::string * StringCrypt::DecryptString( std::string hash ) {

	for ( const auto & cStr : Strings ) {
		if ( cStr.Hash == hash ) {
			auto * result = new std::string;
			result->reserve( cStr.EncryptedString.size( ) ); // Pre-allocate memory

			for ( const auto & cChar : cStr.EncryptedString ) {
				result->push_back( cChar.Letter + cChar._Key );
			}
			return result;
		}
	}
	return nullptr;
}

std::string * StringCrypt::DecryptString( CryptedString str ) {
	auto * result = new std::string;
	result->reserve( str.EncryptedString.size( ) ); // Pre-allocate memory

	for ( const auto & cChar : str.EncryptedString ) {
		result += ( cChar.Letter + cChar._Key );
	}

	return result;
}

void StringCrypt::SaveEncryptedStringsToFile( std::string  filename ) {
	std::ofstream file( filename );

	if ( !file.is_open( ) ) {
		return;
	}

	for ( const auto & cStr : Strings ) {
		file << crypt_str("Hash: ") << cStr.Hash << "\n";
		file << crypt_str("EncryptedString: \n");
		for ( const auto & cChar : cStr.EncryptedString ) {
			file << crypt_str("  Key: ") << cChar._Key << crypt_str(" Letter: ") << static_cast< int >( cChar.Letter ) << "\n";
		}
		file << "\n"; // Adiciona uma linha em branco entre cada string criptografada
	}

	file.close( );
}