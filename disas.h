#ifndef DISAS_H
#define DISAS_H

#include <stdio.h>
//#include "opcodes.c"

#define BITS_01(b) ((b&0xC0) >> 6)
#define BITS_234(b) (((b&0x38) >> 3))
#define BITS_567(b) (b&0x7)

#define MASK_SIB_SCALE(b) (BITS_01(b))
#define MASK_SIB_INDEX(b) (BITS_234(b))
#define MASK_SIB_BASE(b) (BITS_567(b))

#define MASK_MODRM_MOD(b) (BITS_01(b))
#define MASK_MODRM_REG(b) (BITS_234(b))
#define MASK_MODRM_RM(b) (BITS_567(b))

#define RM_SIB 0x04
#define DISP_ONLY 0x05
#define NO_INDEX 0x04

#define MOD_INDIRECT_ADDRESS 0x00
#define MOD_ONE_BYTE_DISPLACEMENT 0x01
#define MOD_FOUR_BYTE_DISPLACEMENT 0x02
#define MOD_REG_ADDRESS 0x03

/*
//Types of operands 
enum OPERAND_TYPE
{
	REG, //Register in mrm byte
	MRM, //Mod + R/M + sib and displacemnt for loc 
	IMM, //Immediate value
	RPC, //Register Plus Command (eg 0x50 for push eax)
	REL8, //Relative one byte offset from current instruction
	REL1632, //Relative 2-4 byte offset from current instruction
	NON //None
};

typedef struct opcode
{
	//Opcode value
	unsigned char v;
	//Extra byte
	unsigned char mor;
	//Direction, size, extended?
	int d, s, e;
	//Operands
	int arg1, arg2, arg3;
	char * name;
} opcode;
*/
//Higher level abstraction of an instruction
typedef struct instruction
{
	opcode op;
	char * instr;
	char * op1, op2;
	int ub;
} instruction;

//8, 16, and 32 bit registers
typedef struct reg {
	char val;
	union {
		struct {
			char * name8;
			char * name16;
			char * name32;
		};
		char * names[3];
	};

} reg;

//Segment registers
enum segment_regs
{
	CS,
	SS,
	DS,
	ES,
	FS,
	GS
};

int is_prefix(char b);
int is_address_size(char b);
int is_operand_size(char b);
int is_seg_override(char b);

void decode_sib(unsigned char b, unsigned char * index, unsigned char * base, int * scale);

void print_hex_long(unsigned char * v, int sign);
void print_hex(unsigned char v);
void printfhex(unsigned char v);

int decode_rm(unsigned char * cb, int size);
int decode_operands(unsigned char * cb, int dir, int size, int immediate);

opcode find_opcode(unsigned char v, unsigned char next);
int decode_instruction(unsigned char * cb, int maxsize);


#endif
