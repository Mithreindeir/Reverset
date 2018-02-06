#ifndef _RFORMAT_H
#define _RFORMAT_H

#include "rdis.h"
#include "ranal.h"
#include "rpipe.h"

#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"


void r_formatted_print(r_pipe * pipe, r_disasm * disas, r_analyzer * anal, uint64_t start, uint64_t end);
void r_formatted_printall(r_pipe * pipe, r_disassembler * disassembler, r_analyzer * anal, uint64_t addr);
void r_formatted_printjump(r_pipe * pipe, r_analyzer * anal, uint64_t addr, uint64_t sb, uint64_t eb);

#endif