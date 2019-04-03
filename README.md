# CEG_4750_Project1

##### Authors: Nathan Dunn and Derek Steinke


## Setup
*Note: This project is intended for use on an Ubuntu System*

1. Install g++ compiler: `sudo apt install g++`
2. Install cryptopp: 
   * `sudo apt-get update`
   * `sudo apt-get install libcrypto++-dev libcrypto++-doc libcrypto++-utils`
3. Compile program: `g++ source.cpp -o source -L. -lcryptopp`