## Reverset

[![Build Status](https://upload.wikimedia.org/wikipedia/commons/f/f8/License_icon-mit-88x31-2.svg)]()
[![Build Status](https://travis-ci.org/Mithreindeir/Reverset.svg?branch=master)](https://travis-ci.org/Mithreindeir/Reverset)

Reverset is a lightweight portable reverse engineering and binary analysis tool. Currently supports the entire standard x86 instruction set, with coming support for x87 fpu, avx, and sse instructions. Supports almost the entire x64 instruction set.
No external dependencies, written completely in C.

# Features

* x86 disassembler
* x64 disassembler
* x86 assembler
* x64 assembler
* Analysis of 32 and 64 bit elf files
* Patching

# How To

After building it, use ./reverset program to open the binary file and enter a reverset shell.

Commands:

* anal				//Automatically disassembles and runs analyzes on program (wip)
* disas here/function/address //Disassembles given start address
* write "bytes"		     //Writes the bytes given as an argument to the current address. Automatically redisassembles after patching.
* asm   "assembly"	     //Assembles using intel format, and returns bytes
* list symbols/functions     //Lists the symbols or symbols that are marked as functions (limited auto function analysis right now)
* goto address/symbol	     //Moves the current address to the new one specified. 
* quit			     //Quits the reverset shell

# Building

Not tested on Windows yet. Use make to compile.

# Example
The main function of reverset:
```C
int main(int argc, char ** argv)
{
	if (argc < 2) {
		printf("Usage: %s file\n", argv[0]);
		return 1;
	}
	reverset * rev = reverset_init();
	reverset_openfile(rev, argv[1]);
	reverset_sh(rev);

	reverset_destroy(rev);
	return 0;
}
```

Example analysis
```ASM
;	XREF TO HERE FROM 0x50d
0x614:   55                      	      push   ebp
0x615:   48 89 e5                	      mov    rbp, rsp
0x618:   48 83 ec 10             	      sub    rsp, 0x10
0x61c:   c7 45 f8 00 00 00 00    	      mov    dword [rbp-0x8], 0
0x623:   c7 45 fc 00 00 00 00    	      mov    dword [rbp-0x4], 0
0x62a:   eb 23                   	   ,=<jmp    0x64f
0x62c:   8b 45 fc                	   |,>mov    eax, dword [rbp-0x4]
0x62f:   2b 45 f8                	   || sub    eax, dword [rbp-0x8]
0x632:   89 c2                   	   || mov    edx, eax	 # (func.foo) arg: 2
0x634:   8b 4d f8                	   || mov    ecx, dword [rbp-0x8]
0x637:   8b 45 fc                	   || mov    eax, dword [rbp-0x4]
0x63a:   01 c1                   	   || add    ecx, eax
0x63c:   8b 45 fc                	   || mov    eax, dword [rbp-0x4]
0x63f:   89 c6                   	   || mov    esi, eax	 # (func.foo) arg: 1
0x641:   89 cf				   || mov    edi, ecx	 # (func.foo) arg: 0
0x643:   e8 b2 ff ff ff          	     	   || call   func.foo(ecx, eax, eax)	 # 0x5fa
0x648:   01 45 f8                	   || add    dword [rbp-0x8], eax
0x64b:   83 45 fc 01             	   || add    dword [rbp-0x4], 0x1
0x64f:   83 7d fc 09             	   `->cmp    dword [rbp-0x4], 0x9
0x653:   7e d7                   	    `<jle    0x62c
0x655:   b8 00 00 00 00          	      mov    eax, 0
0x65a:   c9                      	      leave  
0x65b:   c3                      	      ret    
```
