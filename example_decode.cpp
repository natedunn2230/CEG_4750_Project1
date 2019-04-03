#include<iostream>
#include<fstream>
#include<sstream>
#include<string>
using namespace std;

#include"cryptopp/cryptlib.h"
#include"cryptopp/hex.h"
#include"cryptopp/filters.h"
#include"cryptopp/des.h"
#include"cryptopp/modes.h"

using namespace CryptoPP;
string des_decode(string & cipher,byte key[])
{
	string plain;
	//decode
	try
	{
		ECB_Mode< DES >::Decryption dec;
		dec.SetKey(key, DES::DEFAULT_KEYLENGTH);
		StringSource s(cipher, true, new StreamTransformationFilter(dec, new StringSink(plain)));  
		cout << "recovered text: " << plain<< endl;
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
	return plain;	
}
int main(int argc,char * argv[])
{
	fstream file1;
	fstream file2;
	byte key[DES::DEFAULT_KEYLENGTH];

	if(argc!=4)
	{
		cout<<"usage:des_decode infile outfile key"<<endl;
	}
	file1.open(argv[1],ios::in);
	file2.open(argv[2],ios::out);
	//reading
	stringstream buffer;  
	buffer << file1.rdbuf();  
	string cipher(buffer.str());  
	//get key
	memset(key,0, DES::DEFAULT_KEYLENGTH);
	for(int i=0;i<DES::DEFAULT_KEYLENGTH;i++)
	{
		if(argv[3][i]!='\0')
		{
			key[i]=(byte)argv[3][i];
		}				
		else
		{
			break;
		}
	}
	//print key
	string encoded;
	encoded.clear();
	StringSource(key, sizeof(key), true, new HexEncoder( new StringSink(encoded))); 
	cout << "key: " << encoded<< endl;
	//decode
	string plain=des_decode(cipher,key);
	file2<<plain;
	cout<<"plain text stored in:"<<argv[2]<<endl;
}
