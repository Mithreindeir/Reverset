#ifndef FORMATTER_H
#define FORMATTER_H

#include <stdio.h>
#include <stdlib.h>
#include "instruction.h"
#include "parse_elf.h"

struct jump
{
	int start;
	int end;
	int direction;
	int nested;
};


struct comment
{
	char * comment;
	int addr;
	SYMBOL_TYPE type;
};


typedef struct function
{
	char * fcn;
	int start_addr;
	int end_addr;
	int start_idx;
	int args;
} function;


typedef struct formatter 
{
	struct jump * jumps;
	int num_jumps;

	struct comment * comments;
	int num_comments;

	function * functions;
	int num_functions;
} formatter;

formatter * formatter_init(int start_addr, x86_instruction ** instructions, int num_instructions);
void formatter_analyze(formatter * format, int start_addr, x86_instruction ** instructions, int num_instructions, elf_file * file);
void formatter_printjump(formatter * format, int addr);
void formatter_printcomment(formatter * format, int addr);
void formatter_destroy(formatter * format);

#endif