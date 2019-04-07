/*
    CEG 4750-90 - Information Security
    Dr. Meilin Liu
    Nathan Dunn, Derek Steinke
    Project 1
    4-15-19
*/

#include <iostream>
#include <string>
#include <fstream>
#include <sstream>

#include"crypto++/cryptlib.h"
#include"crypto++/hex.h"
#include"crypto++/filters.h"
#include"crypto++/des.h"
#include "crypto++/modes.h"

using namespace CryptoPP;

std::string decode(std::string & cipherText, byte counter[], byte key[])
{
    std::string plainText; 

    try
    {
        CBC_Mode< DES >::Decryption decrypt;
        decrypt.SetKeyWithIV( key, DES::DEFAULT_KEYLENGTH, counter );
        StringSource(cipherText, true, new StreamTransformationFilter(decrypt, new StringSink(plainText)));

    }
    catch( CryptoPP::Exception& e )
    {
        std::cerr << e.what() << std::endl;
        exit(1);
    }

    return plainText;

}

int main(int argc, char * argv[])
{
    std::cout << "Lets begin decoding >:)" << std::endl;
    //buffer for reading file stream
    std::stringstream stream;

    // streams for each file
    std::fstream inputFile;
    std::fstream outputFile;

    std::string cipherText;

    // for now, i am hard coding test case values
    byte test_key[8] = {0x06, 0x1B, 0xDA, 0x66, 0xB6, 0x74, 0x7E, 0x15};
    byte test_counter[8] = {0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6};

    // check command line args
    if(argc != 3)
    {
        std::cout << "directions: ./ctr_decode <infile> <outfile>" << std::endl;
        exit(0);
    }

    // open up stream to files
    inputFile.open(argv[1], std::ios::in);
    outputFile.open(argv[2], std::ios::out);

    // extract input file data into plaintext string
    stream << inputFile.rdbuf();
    cipherText = stream.str();

    std::cout << "Incoming Ciphertext: " << cipherText << std::endl;

    std::string plainText = decode(cipherText, test_counter, test_key);

    std::cout << "Resulting Plaintext: " << plainText << std::endl;

    outputFile << plainText;

    inputFile.close();
    outputFile.close();

    return 0;
}
