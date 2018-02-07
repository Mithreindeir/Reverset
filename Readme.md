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
Disassembling 0x40de50
Disassembling 0x431821
Disassembling 0x431893
Disassembling 0x431b93
Disassembling 0x43188b
Disassembling 0x43188a
Disassembling 0x431888
Disassembling 0x431882
Disassembling 0x43187b
Disassembling 0x431864
Disassembling 0x43183a
Disassembling 0x43182e
Disassembling 0x43182b
Disassembling 0x431820
Disassembling 0x4009d0
Disassembling 0x400a40
Disassembling 0x400a10
Disassembling 0x400a00
0x400bc0>goto main
0x40356c>print here
//	sym.main
0x40356c:   55                      	       push   rbp
0x40356d:   48 89 e5                	       mov    rbp,rsp
0x403570:   48 81 ec 30 01 00 00    	       sub    rsp,0x130
0x403577:   89 bd dc fe ff ff       	       mov    dword [rbp-0x124],edi
0x40357d:   48 89 b5 d0 fe ff ff    	       mov    qword [rbp-0x130],rsi
0x403584:   64 48 8b 04 25 28 00 .   	       mov    rax,qword fs:[0x28]
0x40358d:   48 89 45 f8             	       mov    qword [rbp-0x8],rax
0x403591:   31 c0                   	       xor    eax,eax
0x403593:   83 bd dc fe ff ff 01    	       cmp    dword [rbp-0x124],0x1
0x40359a:   7f 23                   	       jg     0x4035bf
0x40359c:   48 8b 85 d0 fe ff ff    	       mov    rax,qword [rbp-0x130]
0x4035a3:   48 8b 00                	       mov    rax,qword [rax]
0x4035a6:   48 89 c6                	       mov    rsi,rax
0x4035a9:   bf e0 18 42 00          	       mov    edi, "Usage: %s file"	 # 0x4218e0
0x4035ae:   b8 00 00 00 00          	       mov    eax,0
0x4035b3:   e8 c8 d4 ff ff          	       call   printf	 # 0x400a80
0x4035b8:   b8 01 00 00 00          	       mov    eax,0x1
0x4035bd:   eb 54                   	    ,< jmp    0x403613
0x4035bf:   b8 00 00 00 00          	    |  mov    eax,0
0x4035c4:   e8 ed d6 ff ff          	    |  call   reverset_init	 # 0x400cb6
0x4035c9:   48 89 85 e8 fe ff ff    	    |  mov    qword [rbp-0x118],rax
0x4035d0:   48 8b 85 d0 fe ff ff    	    |  mov    rax,qword [rbp-0x130]
0x4035d7:   48 83 c0 08             	    |  add    rax,0x8
0x4035db:   48 8b 10                	    |  mov    rdx,qword [rax]
0x4035de:   48 8b 85 e8 fe ff ff    	    |  mov    rax,qword [rbp-0x118]
0x4035e5:   48 89 d6                	    |  mov    rsi,rdx
0x4035e8:   48 89 c7                	    |  mov    rdi,rax
0x4035eb:   e8 a9 d7 ff ff          	    |  call   reverset_openfile	 # 0x400d99
0x4035f0:   48 8b 85 e8 fe ff ff    	    |  mov    rax,qword [rbp-0x118]
0x4035f7:   48 89 c7                	    |  mov    rdi,rax
0x4035fa:   e8 2a da ff ff          	    |  call   reverset_sh	 # 0x401029
0x4035ff:   48 8b 85 e8 fe ff ff    	    |  mov    rax,qword [rbp-0x118]
0x403606:   48 89 c7                	    |  mov    rdi,rax
0x403609:   e8 10 d7 ff ff          	    |  call   reverset_destroy	 # 0x400d1e
0x40360e:   b8 00 00 00 00          	    |  mov    eax,0
0x403613:   48 8b 4d f8             	    `> mov    rcx,qword [rbp-0x8]
0x403617:   64 48 33 0c 25 28 00 .   	       xor    rcx,qword fs:[0x28]
0x403620:   74 05                   	    ,< jz     0x403627
0x403622:   e8 49 d4 ff ff          	    |  call   __stack_chk_fail	 # 0x400a70
0x403627:   c9                      	    `> leave  
0x403628:   c3                      	       ret    
0x40356c>


```
