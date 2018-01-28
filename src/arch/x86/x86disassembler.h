#ifndef _X86_DISASSEMBLER_H
#define _X86_DISASSEMBLER_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "x86instructions.h"
#include "../x86common.h"
#include "../../rdis.h"
#include "../../rfile.h"

enum x86_instr_prefix_t
{
	X86_REP,
	X86_REPNE,
	X86_LOCK,
	X86_ADDR_SIZE_OVERRIDE,
	X86_OPERAND_SIZE_OVERRIDE
};

typedef struct x86_instr_prefix {
	int size_override;
	int addr_override;
	char * segment_register;
	char * instr_prefix;
	int extended;
} x86_instr_prefix;

enum x86_opr_t
{
	X86O_INDIR,
	X86O_REL,
	X86O_IMM,
	X86O_MOFF,
	X86O_STR
};

typedef struct x86_instr_operand {
	//Indirect addressing means use data at address (if intel disassembly, surround with [])
	int indirect;
	//0 for 8 bit, 1 for 16 bit, 2 for 32 bit
	int size;
	//Type of operand (x86_opr_t)
	int type;
	char * seg_offset;
	int seg_o;
	union {
		struct {
			char * base;
			char * index;
			int scale;
			int sign;
			uint32_t disp;
		};
		uint32_t relative;
		uint32_t immediate;
		uint32_t moffset;
		char * operand;
	};
} x86_instr_operand;

typedef struct x86_disas_state
{
	unsigned char * stream;
	int operand_start;//The index of the byte after the opcode
	uint32_t address;//The address of the current instruction
	int * iter;
	int addr_override;
	int size_override;
	int opr_size;
	int addr_size;
} x86_disas_state;

x86_instr_prefix x86_instruction_prefix(unsigned char * stream, int * len);

r_disasm * x86_decode_instruction(unsigned char * stream, int address);
x86_instr_operand *x86_decode_operand(char * operand, x86_disas_state *state);
void x86_decode_modrm(x86_instr_operand * opr, x86_disas_state *state);
void x86_decode_sib(x86_instr_operand * opr, x86_disas_state *state);

void x86_print_operand(x86_instr_operand * opr);
char *x86_sprint_operand(x86_instr_operand * opr);

void x86_load_disp32(unsigned int * dest, unsigned char * src);

void x86_sign_extend(x86_instr_operand * op1, x86_instr_operand * op2, x86_instr_operand * op3);
uint32_t x86_resolve_address(uint32_t rel, uint32_t address, int used_bytes);

void x86_disas_meta_type(r_disasm * disas);
void x86_disas_meta_operand(r_disasm * disas, x86_instr_operand * op);

#endif