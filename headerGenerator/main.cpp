#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>

void generateHeader( const std::string & inputFile , const std::string & headerFile , const std::string & arrayName ) {
    std::ifstream file( inputFile , std::ios::binary );
    if ( !file ) {
        std::cerr << "Erro ao abrir o arquivo: " << inputFile << std::endl;
        return;
    }

    std::vector<unsigned char> buffer( ( std::istreambuf_iterator<char>( file ) ) , std::istreambuf_iterator<char>( ) );

    std::ofstream header( headerFile );
    if ( !header ) {
        std::cerr << "Erro ao criar o arquivo: " << headerFile << std::endl;
        return;
    }

    header << "#include <cstdint>\n";
    header << "#include <vector>\n\n";
    header << "const std::vector<std::uint8_t> " << arrayName << " = {\n    ";

    for ( size_t i = 0; i < buffer.size( ); ++i ) {
        header << "0x" << std::hex << std::uppercase << std::setw( 2 ) << std::setfill( '0' ) << ( int ) buffer[ i ];
        if ( i != buffer.size( ) - 1 ) header << ", ";
        if ( ( i + 1 ) % 12 == 0 ) header << "\n    ";
    }

    header << "\n};\n";

    std::cout << "Header gerado com sucesso: " << headerFile << std::endl;
}

int main( int argc , char * argv[ ] ) {
    if ( argc < 4 ) {
        std::cerr << "Uso: " << argv[ 0 ] << " <arquivo_entrada> <arquivo_header> <nome_array>" << std::endl;
        return 1;
    }

    std::string inputFile = argv[ 1 ];
    std::string headerFile = argv[ 2 ];
    std::string arrayName = argv[ 3 ];

    generateHeader( inputFile , headerFile , arrayName );
    return 0;
}
