#ifndef DISASSEMBLER_H
#define DISASSEMBLER_H

#include "disas.h"
#include "parse_elf.h"
#include <stdint.h>


typedef struct function_bounds {
	int start_addr;
	int end_addr;
} function_bounds;

typedef struct disassembler
{
	x86_instruction ** instructions;
	int num_instructions;

	uint32_t * addrstack;
	int num_addresses;

	uint32_t * used_addrstack;
	int unum_addresses;

	function_bounds * bounds;
	int num_bounds;

	formatter * format;

	int linear;
	int recursive;
	int printall;
} disassembler;


void disassemble_file(char * filename, unsigned int args, char * symbol_start, int start_addr);
void disassemble(disassembler * disas, unsigned char * raw_data, int size, int start_addr);

void disassemble_pushaddr(disassembler * disas, int addr);
int disassemble_popaddr(disassembler * disas);

void disassemble_addbound(disassembler * disas, int start_addr, int end_addr);
int disassemble_getbound(disassembler * disas, int addr);

void disassemble_recursive(disassembler * disas, elf_file * file, int start_addr);

void disassemble_analyze(disassembler * disas, elf_file * elf);
void disassemble_print(disassembler * disas);
void disassemble_print_recursive(disassembler * disas, int func_number);

void disassembler_destroy(disassembler * disas);

#endif