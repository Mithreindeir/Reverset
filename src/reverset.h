#ifndef _REVERSET_H
#define _REVERSET_H

#include <stdio.h>
#include <stdlib.h>

#include "dish/dshell.h"
#include "rfile.h"
#include "rdis.h"
#include "ranal.h"
#include "rformat.h"
#include "rpipe.h"
#include "arch/x86/x86disassembler.h"
#include "arch/x86_64/x64assembler.h"
#include "arch/x86/x86assembler.h"
#include "arch/x86_64/x64disassembler.h"

//Currently available disassemblers
static r_disasm*(*disassemblers[])(unsigned char * stream, int address) = {NULL, &x86_decode_instruction, &x64_decode_instruction, NULL};
static unsigned char * (*assemblers[])(char * instruction, uint64_t addr, int * num_bytes) = {NULL, &x86_assemble, &x64_assemble, NULL};

typedef enum r_state
{
	rs_none,
	rs_shell
} r_state;

/* API for Reverset */
typedef struct reverset
{
	//Current address
	uint64_t address;
	//The currently opened file
	r_file * file;
	//The reverset disassembler
	r_disassembler * disassembler;
	//The analyzer
	r_analyzer * anal;
	//Status
	r_state status;
	//output pipe
	r_pipe * pipe;
	//The shell
	dshell *shell;
} reverset;

typedef struct r_cmd
{
	char * name;
	char * usage;
	int(*execute)(reverset * rev, char ** args, int num_args);
} r_cmd;

/*Public API*/
reverset * reverset_init();
void reverset_destroy(reverset * rev);

void reverset_openfile(reverset * rev, char * file, char * perm);
void reverset_sh(reverset * rev);

/*Wrapper functions*/
uint64_t reverset_resolve_arg(reverset * rev, char * arg);
int reverset_analyze(struct text_buffer*buf,int argc, char**argv, void*data);
int reverset_print(struct text_buffer*buf, int argc, char**argv, void*data);
int reverset_disas(reverset * rev, char ** args, int num_args);
int reverset_write(reverset * rev, char ** args, int num_args);
int reverset_goto(struct text_buffer*buf, int argc, char **argv, void*data);
int reverset_asm(struct text_buffer*buf, int argc, char**argv, void*data);
int reverset_quit(struct text_buffer*buf,int argc, char**argv, void*data);
int reverset_list(struct text_buffer*buf, int argc, char **argv, void*data);
int reverset_strmod(reverset * rev, char ** args, int num_args);
int reverset_hex(reverset * rev, char ** args, int num_args);

const static r_cmd r_commands[] = {
	{"disas", "disas here/function/address\n", &reverset_disas},
	{"write", "write \"bytes\"\n", &reverset_write},
	{"/", "/ token\n", &reverset_strmod},
	{"hex", "hex num_bytes\n", &reverset_hex},
};

#endif
