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

//Start and End of functions or other code block type things for recursive descent
typedef struct block_bounds
{
	int start;
	int end;
} block_bounds;

//Disassembler structure. Holds values that allow recursive descent disassembling
typedef struct r_disassembler
{
	r_disasm ** instructions;
	int num_instructions;

	uint64_t * addrstack;
	int num_addresses;

	uint64_t * used_addrstack;
	int unum_addresses;

	block_bounds * bounds;
	int num_bounds;

	int recursive;
} r_disassembler;

rfile* r_openfile(char * filename);
r_disassembler * r_disassemble(rfile * file, r_disasm*(*disassemble)(unsigned char * stream, int address));
void r_disassemble_raw(r_disassembler * disassembler, r_disasm*(*disassemble)(unsigned char * stream, int address), unsigned char * raw_data, int size, int start_addr);

void r_print_disas(r_disassembler * disassembler);

r_disasm * r_disasm_init();
void r_disasm_destroy(r_disasm * disas);
r_disassembler * r_disassembler_init();
void r_disassembler_destroy(r_disassembler * disassembler);
void r_disassembler_pushaddr(r_disassembler * disassembler, uint64_t addr);
uint64_t r_disassembler_popaddr(r_disassembler * disassembler);
void r_disassembler_addbound(r_disassembler * disassembler, uint64_t s, uint64_t e);
uint64_t r_disassembler_getbound(r_disassembler * disassembler, uint64_t addr);

#endif