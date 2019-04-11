# CEG 4750 Project 1
*CEG-4750-90 (Information Security)*

*Dr. Meilin Liu*

*Authors: Nathan Dunn and Derek Steinke*

*4-15-19*

## Compilation
compile source file: `g++ <source_file.cpp> -o <name> -L. -l cryptopp`

## Running Programs
Encoding programs accept an **infile** and an **outfile**. The **infile** contents are encoded and written to the **outfile**

Decoding programs accept an **infile** and an **outfile**. The **infile** contents are decoded and written to the **outfile**
#### CTR MODE 
`./ctr_encode <infile> <outfile>`
`./ctr_decode <infile> <outfile>`
#### CBC MODE
`./cbc_encode <infile> <outfile>`
`./cbc_decode <infile> <outfile>`
