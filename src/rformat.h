#ifndef _RFORMAT_H
#define _RFORMAT_H

#include "rdis.h"
#include "ranal.h"

char * r_formatted_print(r_disasm * disas, r_analyzer * anal, int * iter, uint64_t start, uint64_t end);
char * r_formatted_printall(r_disassembler * disassembler, r_analyzer * anal, uint64_t addr);
char * r_formatted_printjump(r_analyzer * anal, uint64_t addr, uint64_t sb, uint64_t eb);

#endif