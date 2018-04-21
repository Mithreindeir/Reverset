#ifndef RINFO_H
#define RINFO_H

#include "dec/ril.h"

/*Data structures holding analyzed info about the disassembly*/
/*Basic Block*/
typedef struct rbb {
	long size;
	uint64_t start, end;
	int drawn;

	struct rbb **prev, **next;
	int num_prev, num_next;
	ril_instruction * instr;
} rbb;

/*Function struct. Holds start address, end address, name, and xrefs*/
typedef struct r_function {
	int argc;
	char ** args;

	char * name;
	uint64_t start;
	int size;

	int num_locals;
	char ** locals;

	rbb **bbs;
	int nbbs;
} r_function;

/*Branches*/
typedef struct r_branch {
	uint64_t start;
	uint64_t end;
	int conditional;
	int indirect;
	//Start is earlier address. dir is 0 if start is the start 1 if its the end
	int dir;
	//How many branches overlap this
	int nested;
} r_branch;

#endif
