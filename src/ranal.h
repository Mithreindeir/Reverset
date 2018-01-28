#ifndef _R_ANAL_H
#define _R_ANAL_H

#include "rdis.h"
#include "rfile.h"
#include "rmeta.h"

/*Analyzes metadata, instructions, and file data to form comments, xrefs, data sections and more*/
void r_add_xref(r_disasm * to, r_disasm * from);
void r_meta_analyze(r_disasm ** disassembly, int num_instructions, rfile * file);
int r_meta_isaddr(char * operand);
int r_meta_rip_relative(char * operand);


#endif