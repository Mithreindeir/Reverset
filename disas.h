#ifndef DISAS_H
#define DISAS_H

#include <stdio.h>
//#include "opcodes.c"

#define TWO_COMPLEMENT(a) ((256-a))
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

typedef struct sib_byte
{
	int scale;
	unsigned char base;
	unsigned char index;
} sib_byte;

enum mrm_types
{
	indir_disponly,
	indir,
	regm,
	disp8,
	disp32
};

typedef struct mrm_byte
{
	enum mrm_types mt;
	int is_sib;
	//Scale index base
	sib_byte sib;
	//Register for displacement or reg mode
	char regr;

	union {
		//Indirect
		//One byte displacement
		unsigned char disp8;
		//Four byte displacement
		unsigned char disp32[4];
	};

} mrm_byte;

enum opr_t
{
	regr,
	mrm,
	imm,
	rpc,
	rel8,
	rel1632,
	non
};

typedef struct operand
{
	enum opr_t operand_t;
	int size;
	union {
		char regr;
		mrm_byte mrm;
		unsigned char rel8;
		unsigned char rel1632[4];
		unsigned char rpc;
		unsigned char imm8;
		unsigned char imm32[4];
	};
} operand;

//Higher level abstraction of an instruction
typedef struct instruction
{
	action inst_action;
	int num_ops;
	operand op1, op2;
	opcode op;
	char * instr;
	char * op1b;
       	char * op2b;
	int ub;
	unsigned char b[16];
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

int decode_rm(operand * opr, unsigned char * cb, int size);
int decode_operands(instruction * instr, unsigned char * cb, int dir, int size, int immediate);

opcode find_opcode(unsigned char v, unsigned char next);
int decode_instruction(instruction * instr, unsigned char * cb, int maxsize);


void print_operand(operand  opr);
void print_instruction(instruction * instr);


#endif
