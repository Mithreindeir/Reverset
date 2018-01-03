#ifndef FORMATTER_H
#define FORMATTER_H

#include <stdio.h>
#include <stdlib.h>
#include "instruction.h"
#include "parse_elf.h"

#define IN_SECTION(a, b) ((a >= b->addr) && (a <= (b->addr + b->size)))

typedef enum comment_type
{
	c_none,
	c_data_xref,
	c_code_xref,
	c_function_start,
	c_function_call,
	c_string,
	c_array
} comment_type;

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
	int origin_addr;
	comment_type type;
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

formatter * formatter_init(x86_instruction ** instructions, int num_instructions);
void formatter_analyze(formatter * format, int start_addr, x86_instruction ** instructions, int num_instructions, elf_file * file);
void formatter_printjump(formatter * format, int addr);
void formatter_precomment(formatter * format, int addr);
void formatter_postcomment(formatter * format, int addr);
void formatter_addcomment(formatter * format, struct comment c);
void formatter_destroy(formatter * format);
void formatter_strcpy(char * dst, char * src, int max_len);
struct comment * formatter_getcomment(formatter * format, int addr);

#endif