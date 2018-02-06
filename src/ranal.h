#ifndef _R_ANAL_H
#define _R_ANAL_H

#include "rdis.h"
#include "rfile.h"
#include "rmeta.h"

/*Function struct. Holds start address, end address, name, and xrefs*/
typedef struct r_function
{
	int argc;
	char * name;
	uint64_t start;
	uint64_t end;

	uint64_t * xrefs;
	int num_xref;
} r_function;

/*Branches*/
typedef struct r_branch
{
	uint64_t start;
	uint64_t end;
	int conditional;
	int indirect;
	//For ease of analysis, start is always the earlier address. Dir specifies if it is the start (0) or the end(1)
	int dir;
	//How many branches overlap this one. 
	int nested;
} r_branch;

typedef struct r_analyzer
{
	int function;

	r_function * functions;
	int num_functions;

	r_branch * branches;
	int num_branches;
} r_analyzer;

/*Analyzes metadata, instructions, and file data to form comments, xrefs, data sections and more*/
r_analyzer * r_analyzer_init();
void r_analyzer_destroy(r_analyzer * anal);

void r_meta_analyze(r_analyzer * anal, r_disassembler * disassembler, r_file * file);

void r_meta_calculate_branches(r_analyzer * anal, r_disassembler * disassembler);

void r_meta_rip_resolve(r_disassembler * disassembler, r_file * file);
void r_meta_reloc_resolve(r_disassembler * disassembler, r_file * file);

void r_meta_symbol_replace(r_disassembler * disassembler, r_file * file);
void r_meta_string_replace(r_disassembler * disassembler, r_file * file);
void r_meta_find_xrefs(r_disassembler * disassembler, r_file * file);

uint64_t r_meta_get_address(char * operand, int * status);
int r_meta_isaddr(char * operand, int * len);
int r_meta_rip_relative(char * operand);
void r_add_xref(r_disasm * to, r_disasm * from);

#endif