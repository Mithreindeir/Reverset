#ifndef OPERANDS_H
#define OPERANDS_H

#include <string.h>
#include <stdio.h>
#include "opcodes.h"
#include "register.h"

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
//Byte to qword sign extend
#define SIGN_EXTEND(b) ((0x000000FF & b) + (!!(0x00000080 & b))*0xFFFFFF00)

#define NO_INDEX 0x04
#define x86_INVALID -1

enum x86_MOD_DISPLACEMENT {
	MOD_INDIRECT_ADDRESS,
	MOD_ONE_BYTE_DISPLACEMENT,
	MOD_FOUR_BYTE_DISPLACEMENT,
	MOD_REG_ADDRESS,
	RM_SIB,
	DISP_ONLY
};

typedef enum x86_modrm_type
{
	INDIR_DISPONLY,
	INDIR,
	REGM,
	DISP8,
	DISP32,
	DISP32_ONLY
} x86_modrm_type;

typedef struct x86_mem
{
	//For SIB
	int scale;
	int index;
	int base;

	//One or Four byte Displacement
	unsigned char disp8;
	unsigned int disp32;
} x86_mem;

typedef struct x86_modrm_byte
{
	x86_modrm_type type;
	//Is sib
	int sib_byte;
	x86_mem mem;
	x86_reg reg;
} x86_modrm_byte;

typedef struct x86_operand
{
	enum x86_OPERAND_TYPE type;
	int operand_size;

	union {
		x86_reg reg;
		x86_reg rpc;
		x86_modrm_byte modrm;
		//Relative memory
		unsigned char rel8;
		unsigned int rel1632;

		//Immediate memory
		unsigned char imm8;
		unsigned int imm32;
	};

	x86_sreg override;
	int size_override;
	int used_bytes;
} x86_operand;

x86_mem x86_decode_sib(unsigned char sib_byte);
x86_operand x86_decode_rm(unsigned char * raw_bytes, int operand_size, int extension);
void x86_load_disp32(unsigned int * dest, unsigned char * src);
void print_modrm_byte(x86_modrm_byte modrm, x86_sreg seg, int size);
void print_modrm(x86_modrm_byte modrm, int size);
void print_sib(x86_mem mem, x86_modrm_type type);
void x86_print_operand(x86_operand opr);

#endif