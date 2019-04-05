#include<iostream>
#include<fstream>
#include<sstream>
#include<string>
using namespace std;

#include"crypto++/cryptlib.h"
#include"crypto++/hex.h"
#include"crypto++/filters.h"
#include"crypto++/des.h"
#include"crypto++/modes.h"

using namespace CryptoPP;

string des_encode(string & plain,byte key[])
{
	string cipher;
	try
	{
		cout << "plain text: " << plain << endl;
		ECB_Mode<DES>::Encryption enc;
		enc.SetKey(key, DES::DEFAULT_KEYLENGTH);
		StringSource(plain, true, new StreamTransformationFilter(enc, new StringSink(cipher)));//add padding by StreamTransformationFilter 
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
	return cipher;
}

int main(int argc, char * argv[])
{
	fstream file1;
	fstream file2;
	byte key[DES::DEFAULT_KEYLENGTH];

	if(argc!=4)
	{
		cout<<"usage:des_encode infile outfile key"<<endl;
	}
	file1.open(argv[1],ios::in);
	file2.open(argv[2],ios::out);
	//reading
	stringstream buffer;  
	buffer << file1.rdbuf();  
	string plain(buffer.str());  
	//cout<<"plain text:"<<plain<<endl;
	//get key
	memset(key,0,DES::DEFAULT_KEYLENGTH);
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
	//encode
	string cipher=des_encode(plain,key);
	file2<<cipher;
	cout<<"cipher text stored in:"<<argv[2]<<endl;
	
	file1.close();
	file2.close();	
}	
