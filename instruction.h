#ifndef INSTRUCTION_H
#define INSTRUCTION_H

#include "opcodes.h"
#include "operands.h"

typedef enum INSTR_PREFIX
{
	NO_PREFIX,
	LOCK = 0xF0,
	REPNZ = 0xF2,
	REPZ
} INSTR_PREFIX;

typedef struct x86_instruction
{
	int operand_number;
	x86_operand op1, op2;
	x86_opcode op;
	INSTR_PREFIX prefix;

	char * mnemonic;
	char * op1b;
	char * op2b;
	int used_bytes;
	unsigned char b[16];
} x86_instruction;

#endif