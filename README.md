# Reverset
Reverset is a reverse engineering, and binary analysis tool. Currently includes elf parser and partial x86 disassembler.
Currently the disassembler supports around 200 x86 instructions, but still a work in development.
Not currently usable, just does a linear sweep starting from entry point of a couple hundred instructions then exits. 
## Building
gcc -o reverset src/*.c
## Usage
./reverset file
## Example 
This is a snippet (the main function) of the output of ./reverset reverset
```
0x804a648	8d 4c 24 04                    lea ecx, byte [esp] //0x804a648 function: main
0x804a64c	83 e4 f0                       and esp, 0xfffffff0
0x804a64f	ff 71 fc                       push byte [ecx-0x4]
0x804a652	55                             push ebp
0x804a653	89 e5                          mov ebp, esp
0x804a655	51                             push ecx
0x804a656	83 ec 04                       sub esp, 0x4
0x804a659	89 c8                          mov eax, ecx
0x804a65b	83 38 01                       cmp byte [eax], 0x1
0x804a65e	7f 1d                      ,=< jg 0x0804a67d
0x804a660	8b 40 04                   |   mov eax, byte [eax+0x4]
0x804a663	8b 00                      |   mov eax, byte [eax]
0x804a665	83 ec 08                   |   sub esp, 0x8
0x804a668	50                         |   push eax
0x804a669	68 54 26 05 08             |   push 0x8052654
0x804a66e	e8 2d df ff ff             |   call 0x080485a0
0x804a673	83 c4 10                   |   add esp, 0x10
0x804a676	b8 01 00 00 00             |   mov eax, 0x1
0x804a67b	eb 19                      |,< jmp 0x0804a696
0x804a67d	8b 40 04                   `-> mov eax, byte [eax+0x4]
0x804a680	83 c0 04                    |  add eax, 0x4
0x804a683	8b 00                       |  mov eax, byte [eax]
0x804a685	83 ec 0c                    |  sub esp, 0xc
0x804a688	50                          |  push eax
0x804a689	e8 b8 f1 ff ff              |  call 0x08049846
0x804a68e	83 c4 10                    |  add esp, 0x10
0x804a691	b8 00 00 00 00              |  mov eax, 0
0x804a696	8b 4d fc                    `> mov ecx, byte [ebp-0x4]
0x804a699	c9                             leave 
0x804a69a	8d 61 fc                       lea esp, byte [ecx-0x4]
0x804a69d	c3                             ret 

```
