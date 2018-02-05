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

* disas here/function/address //Disassembles given start address
* anal here/function/address //Analyzes given start address. This is done automatically after calling disas
* write "bytes"		     //Writes the bytes given as an argument to the current address. Automatically redisassembles after patching.
* asm   "assembly"	     //Assembles using intel format, and returns bytes
* list symbols/functions     //Lists the symbols or symbols that are marked as functions (at this time there is no automatic function analysis)
* goto address/symbol	     //Moves the current address to the new one specified. 
* quit			     //Quits the reverset shell

# Building

Not tested on Windows yet. Use make to compile.

# Example
The main function of reverset:
```
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
```
./reverset testrev
0x400bc0>disas here
Disassembling 0x400bc0
Disassembling 0x410c60
Disassembling 0x4398e1
Disassembling 0x439953
Disassembling 0x439db8
Disassembling 0x439da8
Disassembling 0x43994b
Disassembling 0x43994a
Disassembling 0x439948
Disassembling 0x439942
Disassembling 0x43993b
Disassembling 0x439924
Disassembling 0x4398fa
Disassembling 0x4398ee
Disassembling 0x4398eb
Disassembling 0x4398e0
Disassembling 0x4009d0
Disassembling 0x400a40
Disassembling 0x400a10
Disassembling 0x400a00
0x400bc0>goto main
0x403cc2>print here
//	sym.main
0x403cc2:   55                      	       push   rbp
0x403cc3:   48 89 e5                	       mov    rbp,rsp
0x403cc6:   48 81 ec 30 01 00 00    	       sub    rsp,0x130
0x403ccd:   89 bd dc fe ff ff       	       mov    dword [rbp-0x124],edi
0x403cd3:   48 89 b5 d0 fe ff ff    	       mov    qword [rbp-0x130],rsi
0x403cda:   64 48 8b 04 25 28 00 .   	       mov    rax,qword fs:[0x28]
0x403ce3:   48 89 45 f8             	       mov    qword [rbp-0x8],rax
0x403ce7:   31 c0                   	       xor    eax,eax
0x403ce9:   83 bd dc fe ff ff 01    	       cmp    dword [rbp-0x124],0x1
0x403cf0:   7f 23                   	       jg     0x403d15
0x403cf2:   48 8b 85 d0 fe ff ff    	       mov    rax,qword [rbp-0x130]
0x403cf9:   48 8b 00                	       mov    rax,qword [rax]
0x403cfc:   48 89 c6                	       mov    rsi,rax
0x403cff:   bf 40 48 42 00          	       mov    edi,0x424840
0x403d04:   b8 00 00 00 00          	       mov    eax,0
0x403d09:   e8 72 cd ff ff          	       call   printf	 # 0x400a80
0x403d0e:   b8 01 00 00 00          	       mov    eax,0x1
0x403d13:   eb 54                   	    ,< jmp    0x403d69
0x403d15:   b8 00 00 00 00          	    |  mov    eax,0
0x403d1a:   e8 97 cf ff ff          	    |  call   reverset_init	 # 0x400cb6
0x403d1f:   48 89 85 e8 fe ff ff    	    |  mov    qword [rbp-0x118],rax
0x403d26:   48 8b 85 d0 fe ff ff    	    |  mov    rax,qword [rbp-0x130]
0x403d2d:   48 83 c0 08             	    |  add    rax,0x8
0x403d31:   48 8b 10                	    |  mov    rdx,qword [rax]
0x403d34:   48 8b 85 e8 fe ff ff    	    |  mov    rax,qword [rbp-0x118]
0x403d3b:   48 89 d6                	    |  mov    rsi,rdx
0x403d3e:   48 89 c7                	    |  mov    rdi,rax
0x403d41:   e8 53 d0 ff ff          	    |  call   reverset_openfile	 # 0x400d99
0x403d46:   48 8b 85 e8 fe ff ff    	    |  mov    rax,qword [rbp-0x118]
0x403d4d:   48 89 c7                	    |  mov    rdi,rax
0x403d50:   e8 dc d2 ff ff          	    |  call   reverset_sh	 # 0x401031
0x403d55:   48 8b 85 e8 fe ff ff    	    |  mov    rax,qword [rbp-0x118]
0x403d5c:   48 89 c7                	    |  mov    rdi,rax
0x403d5f:   e8 ba cf ff ff          	    |  call   reverset_destroy	 # 0x400d1e
0x403d64:   b8 00 00 00 00          	    |  mov    eax,0
0x403d69:   48 8b 4d f8             	    `> mov    rcx,qword [rbp-0x8]
0x403d6d:   64 48 33 0c 25 28 00 .   	       xor    rcx,qword fs:[0x28]
0x403d76:   74 05                   	    ,< jz     0x403d7d
0x403d78:   e8 f3 cc ff ff          	    |  call   __stack_chk_fail	 # 0x400a70
0x403d7d:   c9                      	    `> leave  
0x403d7e:   c3                      	       ret    
0x403cc2>

```
