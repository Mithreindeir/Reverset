## Reverset
[![Build Status](https://upload.wikimedia.org/wikipedia/commons/f/f8/License_icon-mit-88x31-2.svg)]()
[![Build Status](https://travis-ci.org/Mithreindeir/Reverset.svg?branch=master)](https://travis-ci.org/Mithreindeir/Reverset)


<p align="center" img="https://raw.githubusercontent.com/hendrykeren/Reverset/master/.assets/logo/250%20x%20250.png"></p>

Reverset is a lightweight portable reverset engineering and binary analysis tool. No external dependencies, written completely in C. 
#### Currently Being Partially Rewritten to be more architecture independent. No work on new features For ~1 Month



# Features

* x86 disassembler
* x64 disassembler
* x86 assembler
* x64 assembler
* In development Decompiler
	* Intermediate Language
	* Intermediate Language -> SSA
	* Expression Propogation
	* Loop and conditional recovery
	* Upcoming: Disas->microcode->IL, Variable renaming, Address database
* Analysis of 32 and 64 bit elf files
* Basic Block analysis and graphviz control flow output
* Patching
* xref searching
* More

Note: Supports majority of used instructions and but not 100% yet. Still working on support for all x87 fpu/avx/sse/sse2 and misc instructions.

# How To

After building it, use ./reverset program to open the binary file and enter a reverset shell.

Commands:
* anal -> Generic auto analysis of a binary
* print here/func/address/symbol -> Print the disassembly at a location
* printil func -> Print the IL at a function
* goto func/address/symbol -> Moves current location
* list functions/strings/symbols -> List information about a binary
* graph here/func/address/symbol -> Prints basic blocks and graphviz edge data
* asm "assembly" -> Assembles a string using current ISA
* xref to/from here/func/address/symbol -> List xrefs to or from an address
* disas location -> Manual disassembly at a location (currently depreciated)
* help -> Prints this help
* write "bytes" -> Writes the bytes at the current location
* dump (optional -c columns -r rows) address/func/symbol/location -/ "Hexdump"
* quit -> Exits reverset

# Building

Uses several other of my projects on github as submodules.
```
git clone --recurse-submodules https://github.com/mithreindeir/reverset.git
cd reverset
make
```
Not tested on Windows yet.

# Example
An example function to analyze:
```C
int main()
{
	int x = 0;
	for (int i = 0; i < 10; i++) {
		x += foo(x+i, i, i-x);
	}
	return 0;
}
```

Output of different commands

printil func.main ->
``` C
0x614:
	push( ebp_0 )
	rbp_1 = rsp_0
	rsp_1 = rsp_0 - 0x10
	[rbp_1-0x8] = 0
	[rbp_1-0x4] = 0
	goto 0x64f
0x62c:
	eax_1 = [rbp_1-0x4]
	eax_2 = [rbp_1-0x4] - [rbp_1-0x8]
	edx_1 = ([rbp_1-0x4] - [rbp_1-0x8])
	ecx_1 = [rbp_1-0x8]
	eax_3 = [rbp_1-0x4]
	ecx_2 = [rbp_1-0x8] + [rbp_1-0x4]
	eax_4 = [rbp_1-0x4]
	esi_1 = [rbp_1-0x4]
	edi_1 = ([rbp_1-0x8] + [rbp_1-0x4])
	0x5fa()
	[rbp_1-0x8] = [rbp_1-0x8] + [rbp_1-0x4]
	[rbp_1-0x4] = [rbp_1-0x4] + 0x1
0x64f:
	[rbp_1-0x4] ? 0x9
	if ( <= ) goto 0x62c
0x655:
	eax_5 = 0
	return 


```

graph func.main ->
```ASM
digraph F {
	"(0x614-0x62c)" -> "(0x64f-0x655)"
	"(0x62c-0x64f)" -> "(0x64f-0x655)"
	"(0x64f-0x655)" -> "(0x62c-0x64f)"
	"(0x64f-0x655)" -> "(0x655-0x65c)"
}
,--------------------------.
|0x614:                    |
|push   ebp                |
|mov    rbp, rsp           |
|sub    rsp, 0x10          |
|mov    dword [local_8h], 0|
|mov    dword [local_4h], 0|
|jmp    0x64f              |
`--------------------------'
,----------------------------.
|0x64f:                      |
|cmp    dword [local_4h], 0x9|
|jle    0x62c                |
`----------------------------'
,------------------------------.
|0x62c:                        |
|mov    eax, dword [local_4h]  |
|sub    eax, dword [local_8h]  |
|mov    edx, eax               |
|mov    ecx, dword [local_8h]  |
|mov    eax, dword [local_4h]  |
|add    ecx, eax               |
|mov    eax, dword [local_4h]  |
|mov    esi, eax               |
|mov    edi, ecx               |
|call   func.foo(ecx, eax, eax)|
|add    dword [local_8h], eax  |
|add    dword [local_4h], 0x1  |
`------------------------------'
,-------------.
|0x655:       |
|mov    eax, 0|
|leave        |
|ret          |
`-------------'

```
print func.main
```ASM
;	XREF TO HERE FROM 0x50d
//	func.main()
0x614:   55                      	      push   ebp
0x615:   48 89 e5                	      mov    rbp, rsp
0x618:   48 83 ec 10             	      sub    rsp, 0x10
0x61c:   c7 45 f8 00 00 00 00    	      mov    dword [local_8h], 0
0x623:   c7 45 fc 00 00 00 00    	      mov    dword [local_4h], 0
0x62a:   eb 23                   	   ,=<jmp    0x64f
;	XREF TO HERE FROM 0x653
0x62c:   8b 45 fc                	   |,>mov    eax, dword [local_4h]
0x62f:   2b 45 f8                	   || sub    eax, dword [local_8h]
0x632:   89 c2                   	   || mov    edx, eax	 # (func.foo) arg: 2
0x634:   8b 4d f8                	   || mov    ecx, dword [local_8h]
0x637:   8b 45 fc                	   || mov    eax, dword [local_4h]
0x63a:   01 c1                   	   || add    ecx, eax
0x63c:   8b 45 fc                	   || mov    eax, dword [local_4h]
0x63f:   89 c6                   	   || mov    esi, eax	 # (func.foo) arg: 1
0x641:   89 cf                   	   || mov    edi, ecx	 # (func.foo) arg: 0
0x643:   e8 b2 ff ff ff          	      || call	func.foo(ecx, eax, eax)
0x648:   01 45 f8                	   || add    dword [local_8h], eax
0x64b:   83 45 fc 01             	   || add    dword [local_4h], 0x1
;	XREF TO HERE FROM 0x62a
0x64f:   83 7d fc 09             	   `->cmp    dword [local_4h], 0x9
0x653:   7e d7                   	    `<jle    0x62c
0x655:   b8 00 00 00 00          	      mov    eax, 0
0x65a:   c9                      	      leave
0x65b:   c3                      	      ret

```
