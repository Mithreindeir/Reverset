#ifndef _RFORMAT_H
#define _RFORMAT_H

#include "rdis.h"
#include "ranal.h"
#include "rpipe.h"
#include "rinfo.h"
#include "dish/ascii/draw.h"

#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"


void r_formatted_graph(struct text_buffer *textb, r_disassembler *disassembler, r_analyzer *anal, rbb *bb);
void r_formatted_rect(struct text_buffer *textb, r_disassembler *disassembler, r_analyzer *anal, rbb *bb);
void r_formatted_print(struct text_buffer *textb, r_disasm * disas, r_analyzer * anal, uint64_t start, uint64_t end);
void r_formatted_printall(struct text_buffer *textb, r_disassembler * disassembler, r_analyzer * anal, uint64_t addr, int max);
void r_formatted_printjump(struct text_buffer *textb, r_analyzer * anal, uint64_t addr, uint64_t sb, uint64_t eb);

#endif
