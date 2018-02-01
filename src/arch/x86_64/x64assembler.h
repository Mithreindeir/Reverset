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
#define X64_NUMBER_OP(type) (type == X64_IMM || type == X64_REL || type == X64_MEM)

struct x64_assemble_op
{
	int mode;
	int size;
	char * operand;
	char * encoded;
	int num_bytes;
};

struct x64_asm_op
{
	unsigned char * bytes;
	int num_bytes;
};

struct x64_indirect
{
	int size;
	int sib;//1 if sib
	int disp_size;//0=no disp, 1 = 1 byte 4 = 4 byte
	uint32_t disp;
	int  base;//-1 if nonexistant
	int index;//-1 if nonexistant
	int  scale;//-1 if nonexistant
};

struct x64_assemble_op x64_assembler_type(char * operand);
char * no_space_strdup(char * str);
char * strtok_dup(char * string, char * delim, int last);
void x64_assemble(char * instruction);
void x64_encode_modrm(struct x64_asm_op * asm_op, struct x64_assemble_op * operands, int num_operand, int extended);
void x64_retreive_indirect(char * operand,struct  x64_indirect * indir);

int x64_indirect_prefix(char * operand);
int x64_register_index(char * reg);
int x64_find_instruction(char * mnemonic, struct x64_assemble_op * operands, int num_operands, int * extended);
int x64_size_compatible(int size1, int size2);
int x64_operands_compatible(x64_instruction instr, struct x64_assemble_op * operands, int num_operand);
void x64_add_byte(struct x64_asm_op * op, unsigned char byte);
void x64_add_int32(struct x64_asm_op * op, uint32_t bint);


#endif