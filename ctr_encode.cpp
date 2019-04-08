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
#include"crypto++/modes.h"

# define BLOCK_SIZE 8

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

/*
    returns char array of padded message
    assigns the size of the array to length
*/
unsigned char * applyPadding(std::string input, int * length)
{  
    int messageLength = input.length();
    int paddingValue = BLOCK_SIZE - messageLength % BLOCK_SIZE;

    int totalSize = messageLength + paddingValue;

    *length = totalSize;

    unsigned char * data = new unsigned char[totalSize];

    // transfer non padding values to char array
    for(int i = 0; i < totalSize; i++)
    {
        if(i < messageLength)
        {
            data[i] = input[i];
        }
        else
        {
            data[i] = (unsigned char)paddingValue;
        }
    }
        
    return data;
}

int main(int argc, char * argv[])
{
    //buffer for reading file stream
    std::stringstream stream;

    // streams for each file
    std::fstream inputFile;
    std::fstream outputFile;

    std::string plainText;

    unsigned char key[BLOCK_SIZE] = {0x06, 0x1B, 0xDA, 0x66, 0xB6, 0x74, 0x7E, 0x15};
    unsigned char counter[BLOCK_SIZE] = {0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6};

    // check command line args
    if(argc != 3)
    {
        std::cout << "directions: ./ctr_encode <infile> <outfile>" << std::endl;
        exit(0);
    }

    // open up stream to files
    inputFile.open(argv[1], std::ios::in);
    outputFile.open(argv[2], std::ios::out);

    // extract input file data into plaintext string
    stream << inputFile.rdbuf();
    plainText = stream.str();

    std::cout << "Incoming Plaintext: " << plainText << std::endl;

    // total size of padded data
    int dataSize;

    // padded bytes extracted from plaintext
    unsigned char * plainData = applyPadding(plainText, &dataSize);

    // cipher data will be stored here
    unsigned char * cipherData = new unsigned char[dataSize];
    
    int counterN = 0;

    // for every 8 byte chunk, compute ctr block
    for(int i = 0; i < dataSize; i += BLOCK_SIZE)
    {
        int outputIndex = 0;
        unsigned char output[BLOCK_SIZE];

        // compute new counter each block (counter + 1)
        counter[BLOCK_SIZE - 1] = counter[BLOCK_SIZE - 1] + counterN;

        // get result from DES of key and counter...
        des_encryption_8(counter, key, output);

        // xor result with plaintext block to get ciphertext block
        for(int j = i; j < i + BLOCK_SIZE; j++)
        {
            cipherData[j] = plainData[j] ^ output[outputIndex];
            outputIndex++;
        }
    }

    std::cout << "Resulting CipherText: " << cipherData << std::endl;

    outputFile << cipherData;

    inputFile.close();
    outputFile.close();

    return 0;
}
