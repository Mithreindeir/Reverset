#ifndef _RDIS_H
#define _RDIS_H

#include "rfile.h"
#include "file/elf/read_elf.h"
#include "rmeta.h"

//Generic disassembly format for printing. Supports up to 3 operands
//Instruction op1, op2, op3
//Includes start address and used bytes
typedef struct r_disasm
{
	uint32_t address;
	unsigned char * raw_bytes;
	int used_bytes;

	char * mnemonic;
	char * op[3];
	int num_operands;

	r_meta * metadata;
} r_disasm;

rfile* r_openfile(char * filename);
r_disasm ** r_disassemble(rfile * file, r_disasm*(*disassemble)(unsigned char * stream, int address), int * num_disas);
void r_print_disas(r_disasm ** disassembly, int num_disassembly);

r_disasm * r_disasm_init();
void r_disasm_destroy(r_disasm * disas);

#endif