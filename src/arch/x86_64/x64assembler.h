#ifndef _X64_ASSEMBLE_H
#define _X64_ASSEMBLE_H

#include <stdint.h>
#include "x64instructions.h"
#include "x64disassembler.h"

//Takes register index and returns size
#define X64_REG_SIZE(idx) (idx%4+1)
//Takes register index and returns binary form of how processors refer to it
#define X64_REG_BIN(idx) (idx/4)
//size = (i-1)%4 + 1;
//
#define X64_NUMBER_OP(type) (type == X64_IMM || type == X64_REL || type == X64_MEM || type == X64_DIRECT_ADDRESSING)

struct x64_assemble_op
{
	int mode;
	int size;
	int relative_size;
	int opr_size;
	int addr_size;
	char * operand;

	int rexb;
	int rexr;
	int rexx;
};

struct x64_asm_bytes
{
	unsigned char * bytes;
	int num_bytes;
};

struct x64_indirect
{
	int rexb;
	int rexx;
	int addr_size;
	int sib;//1 if sib
	int disp_size;//0=no disp, 1 = 1 byte 4 = 4 byte
	uint32_t disp;
	int  base;//-1 if nonexistant
	int index;//-1 if nonexistant
	int  scale;//-1 if nonexistant
};

unsigned char * x64_assemble(char * instruction, uint64_t addr, int * num_bytes);

struct x64_assemble_op x64_assembler_type(char * operand);
char * no_space_strdup(char * str);
char * strtok_dup(char * string, char * delim, int last);
void x64_calculate_rex(struct x64_asm_bytes * op, struct x64_assemble_op * operands, int num_operands);
void x64_encode_modrm(struct x64_asm_bytes * asm_op, struct x64_assemble_op * operands, int num_operand, int extended);
void x64_retrieve_indirect(char * operand, struct  x64_indirect * indir);

int x64_relative_size(char * operand, uint64_t address);
int x64_indirect_prefix(char * operand);
int x64_register_index(char * reg);
int x64_find_instruction(char * mnemonic, uint64_t addr,  struct x64_assemble_op * operands, int num_operands, int * extended);
int x64_size_compatible(int type, int size1, int size2);
int x64_operands_compatible(x64_instruction instr, uint64_t addr, struct x64_assemble_op * operands, int num_operand);
void x64_add_byte(struct x64_asm_bytes * op, unsigned char byte);
void x64_add_int32(struct x64_asm_bytes * op, uint32_t bint);
void x64_add_byte_prefix(struct x64_asm_bytes * op, unsigned char byte);
int x64_scale(int scalef);

#endif