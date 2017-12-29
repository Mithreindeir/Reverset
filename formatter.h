#ifndef FORMATTER_H
#define FORMATTER_H
#include <stdio.h>
#include "instruction.h"

struct jump
{
	int start;
	int end;
	//1 for down 0 for up	
	int direction;
	//How many jumps are contained within this
	/*
	jmp x //nest 0
	jmp y // nest 1
	x
	y
	*/
	int nested;
};

typedef struct formatter 
{
	struct jump * jumps;
	int num_jumps;
} formatter;

formatter * formatter_init(int start_addr, x86_instruction ** instructions, int num_instructions);
void formatter_printline(formatter * format, int addr);
void formatter_destroy(formatter * format);

#endif