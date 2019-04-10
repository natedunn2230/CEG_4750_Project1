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

#define BLOCK_SIZE 8

using namespace CryptoPP;

// in CTR, the key and counter are run through an encryption algorithm
void des_encryption_8(unsigned char *input, unsigned char *key, unsigned char *output)
{

    DESEncryption desEncryptor;
    unsigned char xorBlock[BLOCK_SIZE];
    memset(xorBlock, 0, BLOCK_SIZE);
    desEncryptor.SetKey(key, BLOCK_SIZE);
    desEncryptor.ProcessAndXorBlock(input, xorBlock, output);

}

// unpack incoming ciphertext into char array
unsigned char * getData(std::string input)
{
    unsigned char * data = new unsigned char[input.length()];

    // map each character from string to the array
    for(int i = 0; i < input.length(); i++)
    {
        data[i] = input[i];
    }

    return data;
}

// obtain value of padding and update size of data
void removePadding(unsigned char * data, int * size)
{
    // obtain last byte to obtain padding value
    unsigned char paddingValue = data[*size - 1];

    *size = *size - paddingValue;
}

int main(int argc, char * argv[])
{
    //buffer for reading file stream
    std::stringstream stream;

    // streams for each file
    std::fstream inputFile;
    std::fstream outputFile;

    std::string cipherText;

    unsigned char key[BLOCK_SIZE] = {0x06, 0x1B, 0xDA, 0x66, 0xB6, 0x74, 0x7E, 0x15};
    unsigned char counter[BLOCK_SIZE] = {0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6};

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

    // unpack incoming ciphertext into a char array
    int dataSize = cipherText.length();
    unsigned char * cipherData = getData(cipherText);
    unsigned char * plainData = new unsigned char[dataSize];
    
    int counterN = 0;

    // process each ctr block into plaintext, for every 8 byte chunk
    for(int i = 0; i < dataSize; i += BLOCK_SIZE)
    {
        int outputIndex = 0;
        unsigned char output[BLOCK_SIZE];

        // compute new counter each block (counter + 1)
        counter[BLOCK_SIZE - 1] = counter[BLOCK_SIZE - 1] + counterN;

        // get result from DES of key and counter...
        des_encryption_8(counter, key, output);

         // xor result with ciphertext block to get plaintext block
        for(int j = i; j < i + BLOCK_SIZE; j++)
        {
            plainData[j] = cipherData[j] ^ output[outputIndex];
            outputIndex++;
        }

    }

    // detect padding and update size
    removePadding(plainData, &dataSize);

    std::string plainText;
    for(int i = 0; i < dataSize; i++)
    {
        plainText += plainData[i];
    }

    std::cout << "Resulting Plaintext: " << plainText << std::endl;

    outputFile << plainText;

    inputFile.close();
    outputFile.close();

    return 0;
}
