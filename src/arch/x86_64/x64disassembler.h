#ifndef _X64_DISASSEMBLER_H
#define _X64_DISASSEMBLER_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "x64instructions.h"
#include "../x86common.h"
#include "../../rdis.h"
#include "../../rfile.h"

enum x64_instr_prefix_t
{
	X64_REP,
	X64_REPNE,
	X64_LOCK,
	X64_ADDR_SIZE_OVERRIDE,
	X64_OPERAND_SIZE_OVERRIDE
};

//Bit mask for rex prefix
//  0000wrxb
#define X64_REX_PREFIX(v) (v >= 0x40 && v < 0x50)
#define X64_MASK_REX(v) (v==0)			//Access to new 8 bit registers
#define X64_MASK_REX_B(v) ((v & 0x1) != 0)	//Extension to r/m field, base field, or opcode reg field
#define X64_MASK_REX_X(v) ((v & 0x2) != 0)	//Extension of SIB index field
#define X64_MASK_REX_R(v) ((v & 0x4) != 0)	//Extension of modr/m reg field
#define X64_MASK_REX_W(v) ((v & 0x8) !=0)	//64 bit operand size

enum x64_rex_prefix
{
	X64_REX,	//0000
	X64_REX_B,		//0001
	X64_REX_X,		//0010
	X64_REX_XB,		//0011
	X64_REX_R,		//0100
	X64_REX_RB,		//0101
	X64_REX_RX,		//0110
	X64_REX_RXB,	//0111
	X64_REX_W,		//1000
	X64_REX_WB,		//1001
	X64_REX_WX,		//1010
	X64_REX_WXB,	//1011
	X64_REX_WR,		//1100
	X64_REX_WRB,	//1101
	X64_REX_WRX,	//1110
	X64_REX_WRXB	//1111
};


typedef struct x64_instr_prefix {
	int size_override;
	int addr_override;
	int fp_size;
	char * segment_register;
	char * instr_prefix;
	int extended;
	int rex_prefix;
} x64_instr_prefix;

enum x64_opr_t
{
	X64O_INDIR,
	X64O_REL,
	X64O_IMM,
	X64O_MOFF,
	X64O_STR
};

typedef struct x64_instr_operand {
	//Indirect addressing means use data at address (if intel disassembly, surround with [])
	int indirect;
	//0 for 8 bit, 1 for 16 bit, 2 for 32 bit
	int size;
	//Type of operand (x64_opr_t)
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
		uint64_t relative;
		uint64_t immediate;
		uint64_t moffset;
		char * operand;
	};
} x64_instr_operand;

typedef struct x64_disas_state
{
	unsigned char * stream;
	int operand_start;//The index of the byte after the opcode
	uint64_t address;//The address of the current instruction
	int * iter;
	int addr_override;
	int size_override;
	int opr_size;
	int addr_size;
	int rex;
	int seg_o;
	char * seg_reg;
} x64_disas_state;

x64_instr_prefix x64_instruction_prefix(unsigned char * stream, int * len);

r_disasm * x64_decode_instruction(unsigned char * stream, int address);
x64_instr_operand *x64_decode_operand(char * operand, x64_disas_state *state);
void x64_decode_modrm(x64_instr_operand * opr, x64_disas_state *state);
void x64_decode_sib(x64_instr_operand * opr, x64_disas_state *state);
char * x64_get_register(int r, int size, int rexb);

void x64_print_operand(x64_instr_operand * opr);
char *x64_sprint_operand(x64_instr_operand * opr);

void x64_load_disp32(unsigned int * dest, unsigned char * src);

void x64_sign_extend(x64_instr_operand * op1, x64_instr_operand * op2, x64_instr_operand * op3);
uint64_t x64_resolve_address(uint64_t rel, uint64_t address, int used_bytes);

void x64_disas_meta_type(r_disasm * disas);
void x64_disas_meta_operand(r_disasm * disas, x64_instr_operand * op);

#endif
