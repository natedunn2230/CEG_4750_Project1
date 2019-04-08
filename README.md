# CEG_4750_Project1

##### Authors: Nathan Dunn and Derek Steinke


## Setup
*Note: This project is intended for use on an Ubuntu System*

1. Install g++ compiler: `sudo apt install g++`
2. Install cryptopp: 
   * `sudo apt-get update`
   * `sudo apt-get install libcrypto++-dev libcrypto++-doc libcrypto++-utils`
3. Compile program: `g++ source.cpp -o source -L. -lcryptopp`


## Running Programs
### Example Files
#### Encryption
1. After compiling program into example_encode: `./example_encode MSG1 MSG1.ee <8-char-key-string>`
#### Decryption
2. After compiling program into example_decode: `./example_decode MSG1.ee MSG1.dd <8-char-key-string>`

We can verify that MSG1 and MSG1.dd are identical: `diff MSG1 MSG1.dd`

Viewing file contents (hex and big endian): `od -x --endian=big <file>`