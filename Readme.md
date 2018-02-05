## Reverset

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
A test program of:
```
int function_foo()
{
	int a = 10;
	if (a) return 10;
	return 5;
}

int main(int argc, char ** argv)
{
	char * str = "Test\n";
	printf("This is a test program for disassembly %d\n", function_foo());
	printf("%s", str);
	return 0;
}
```

Disassembles to (snippet of full disassembly): 
```
//	sym.function_foo
0x400526:   55                      	push   rbp
0x400527:   48 89 e5                	mov    rbp,rsp
0x40052a:   c7 45 fc 0a 00 00 00    	mov    dword [rbp-0x4],0xa
0x400531:   83 7d fc 00             	cmp    dword [rbp-0x4],0
0x400535:   74 07                   	jz     0x40053e
0x400537:   b8 0a 00 00 00          	mov    eax,0xa
0x40053c:   eb 05                   	jnp    0x400543
0x40053e:   b8 05 00 00 00          	mov    eax,0x5
0x400543:   5d                      	pop    rbp
0x400544:   c3                      	ret    
//	sym.main
0x400545:   55                      	push   rbp
0x400546:   48 89 e5                	mov    rbp,rsp
0x400549:   48 83 ec 20             	sub    rsp,0x20
0x40054d:   89 7d ec                	mov    dword [rbp-0x14],edi
0x400550:   48 89 75 e0             	mov    qword [rbp-0x20],rsi
0x400554:   48 c7 45 f8 28 06 40 .   	mov    qword [rbp-0x8], "Test"	 # 0x400628
0x40055c:   b8 00 00 00 00          	mov    eax,0
0x400561:   e8 c0 ff ff ff          	call   function_foo	 # 0x400526
0x400566:   89 c6                   	mov    esi,eax
0x400568:   bf 30 06 40 00          	mov    edi, "This is a test program for disassembly %d"	 # 0x400630
0x40056d:   b8 00 00 00 00          	mov    eax,0
0x400572:   e8 89 fe ff ff          	call   0x400400
0x400577:   48 8b 45 f8             	mov    rax,qword [rbp-0x8]
0x40057b:   48 89 c6                	mov    rsi,rax
0x40057e:   bf 5b 06 40 00          	mov    edi,0x40065b
0x400583:   b8 00 00 00 00          	mov    eax,0
0x400588:   e8 73 fe ff ff          	call   0x400400
0x40058d:   b8 00 00 00 00          	mov    eax,0
0x400592:   c9                      	leave  
0x400593:   c3                      	ret    
0x400594:   66 2e 0f 1f 84 00 00 .   	nop    word cs:[rax+rax]
0x40059e:   66 90                   	nop    

```
