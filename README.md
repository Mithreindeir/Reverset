# Reverset
Reverset is a reverse engineering, and binary analysis tool. Currently includes elf parser and partial x86 disassembler.
Currently the disassembler supports around 200 x86 instructions, but still a work in development.
Not currently usable, just does a linear sweep starting from entry point of a couple hundred instructions then exits. 
## Building
gcc -o reverset *.c
## Usage
./reverset file
