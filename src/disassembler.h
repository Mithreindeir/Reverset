#ifndef DISASSEMBLER_H
#define DISASSEMBLER_H

#include "disas.h"
#include "parse_elf.h"

typedef struct disassembler
{
	unsigned char * raw_data;
	int size;

	x86_instruction ** instructions;
	int num_instructions;

	formatter * format;
} disassembler;


void disassemble_file(char * filename);
void disassemble(disassembler * disas);
void disassemble_analyze(disassembler * disas, elf_file * elf);
void disassemble_print(disassembler * disas, int entry_point);

void disassembler_destroy(disassembler * disas);

#endif