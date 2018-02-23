#ifndef _R_ANAL_H
#define _R_ANAL_H

#include "rdis.h"
#include "rfile.h"
#include "rmeta.h"
#include "arch/x86common.h"

static char * unix64_cc[] = {
	"rdi",
	"rsi",
	"rdx",
	"rcx",
	"r8",
	"r9",
	"stk"
};
/*Function struct. Holds start address, end address, name, and xrefs*/
typedef struct r_function
{
	int argc;
	char ** args;
	
	char * name;
	uint64_t start;
	int size;

	int num_locals;
	char ** locals;
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

void r_meta_auto(r_analyzer * anal, r_disassembler * disassembler, r_file * file);
void r_meta_analyze(r_analyzer * anal, r_disassembler * disassembler, r_file * file);

void r_meta_calculate_branches(r_analyzer * anal, r_disassembler * disassembler);

void r_meta_rip_resolve(r_disassembler * disassembler, r_file * file);
void r_meta_reloc_resolve(r_disassembler * disassembler, r_file * file);

void r_meta_symbol_replace(r_disassembler * disassembler, r_file * file);
void r_meta_string_replace(r_disassembler * disassembler, r_file * file);
void r_meta_func_replace(r_disassembler * disassembler, r_file * file, r_analyzer * anal);
void r_meta_find_xrefs(r_disassembler * disassembler, r_file * file);

uint64_t r_meta_get_address(char * operand, int * status);
int r_meta_isaddr(char * operand, int * len);
int r_meta_rip_relative(char * operand);
int r_meta_indirect_address(char * operand);
void r_add_xref(r_disasm * to, r_disasm * from, int type);

/*Very Rudimentary Argument Recognition by using the current ABI's calling convention*/
void r_function_arguments(r_disassembler * disassembler, r_analyzer * anal, r_function * func, r_abi abi);
void r_function_arg_replacer(r_disassembler * disassembler, int idx, r_function * func, r_abi abi);
int r_function_get_stack_args(char * operand, r_abi abi);
int r_function_get_stack_locals(char * operand, r_abi abi);

/*Local Naming through finding stack offsets*/
void r_function_locals(r_disassembler * disassembler, r_function * func, r_abi abi);

#endif