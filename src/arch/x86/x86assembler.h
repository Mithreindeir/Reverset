#ifndef _X86_ASSEMBLE_H
#define _X86_ASSEMBLE_H

#include <stdint.h>
#include "x86instructions.h"
#include "x86disassembler.h"

//Takes register index and returns size
#define X86_REG_SIZE(idx) (idx%4+1)
//Takes register index and returns binary form of how processors refer to it
#define X86_REG_BIN(idx) (idx/4)

#define X86_NUMBER_OP(type) (type == X86_IMM || type == X86_REL || type == X86_MEM || type == X86_DIRECT_ADDRESSING)

struct x86_assemble_op
{
	int mode;
	int size;
	int relative_size;
	int opr_size;
	int addr_size;
	char * operand;
};

struct x86_asm_bytes
{
	unsigned char * bytes;
	int num_bytes;
};

struct x86_indirect
{
	int addr_size;
	int sib;//1 if sib
	int disp_size;//0=no disp, 1 = 1 byte 4 = 4 byte
	uint32_t disp;
	int  base;//-1 if nonexistant
	int index;//-1 if nonexistant
	int  scale;//-1 if nonexistant
};

unsigned char * x86_assemble(char * instruction, uint64_t addr_s, int * num_bytes);

struct x86_assemble_op x86_assembler_type(char * operand);
void x86_encode_modrm(struct x86_asm_bytes * asm_op, struct x86_assemble_op * operands, int num_operand, int extended);
void x86_retrieve_indirect(char * operand, struct  x86_indirect * indir);

int x86_relative_size(char * operand, uint32_t address);
int x86_indirect_prefix(char * operand);
int x86_register_index(char * reg);
int x86_find_instruction(struct x86_asm_bytes * asm_op, char * mnemonic, uint32_t addr,  struct x86_assemble_op * operands, int num_operands, int * extended);
int x86_size_compatible(int type, int size1, int size2);
int x86_operands_compatible(x86_instruction instr, uint32_t addr, struct x86_assemble_op * operands, int num_operand);
void x86_add_byte(struct x86_asm_bytes * op, unsigned char byte);
void x86_add_int32(struct x86_asm_bytes * op, uint32_t bint);
void x86_add_byte_prefix(struct x86_asm_bytes * op, unsigned char byte);
int x86_scale(int scalef);

#endif