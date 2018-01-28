#ifndef _ARM_DISASSEMBLE_H
#define _ARM_DISASSEMBLE_H

#include "arminstructions.h"

typedef struct arm_instr
{
	int condition;
	char * mnemonic;

} arm_instr;

void arm_decode_instruction(unsigned char * stream);

#endif