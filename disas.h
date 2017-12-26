#ifndef DISAS_H
#define DISAS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "operands.h"
#include "instruction.h"
#include "opcodes.h"
#include "colors.h"
#include "parse_elf.h"

int is_seg_override(char b);
x86_opcode x86_find_opcode(unsigned char v, unsigned char next, unsigned char two_byte);

void print_instruction(x86_instruction * instr);

void x86_decode_operands(x86_instruction * instr, x86_opcode opcode, unsigned char * raw_bytes);
x86_instruction  * x86_decode_instruction(unsigned char * raw_bytes, int len);

#endif
