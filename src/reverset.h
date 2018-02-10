#ifndef _REVERSET_H
#define _REVERSET_H

#include <stdio.h>
#include <stdlib.h>

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
void reverset_execute(reverset * rev, char * cmd);
void reverset_eval(reverset * rev, int argc, char ** argv);
void reverset_sh(reverset * rev);

/*Private Functions for reverset shell*/
char * reverset_readline();
char ** reverset_split_line(char * line, int * num_args);
char * reverset_split(char * first);

/*Wrapper functions*/
uint64_t reverset_resolve_arg(reverset * rev, char * arg);
int reverset_analyze(reverset * rev, char ** args, int num_args);
int reverset_print(reverset * rev, char ** args, int num_args);
int reverset_disas(reverset * rev, char ** args, int num_args);
int reverset_write(reverset * rev, char ** args, int num_args);
int reverset_goto(reverset * rev, char ** args, int num_args);
int reverset_asm(reverset * rev, char ** args, int num_args);
int reverset_quit(reverset * rev, char ** args, int num_args);
int reverset_list(reverset * rev, char ** args, int num_args);
int reverset_strmod(reverset * rev, char ** args, int num_args);
int reverset_hex(reverset * rev, char ** args, int num_args);

const static r_cmd r_commands[] = {
	{"print","print all/here/function/address\n", &reverset_print},
	{"anal", "anal here/function/address\n", &reverset_analyze},
	{"disas", "disas here/function/address\n", &reverset_disas},
	{"write", "write \"bytes\"\n", &reverset_write},
	{"goto", "goto address/symbol\n", &reverset_goto},
	{"asm", "asm \"assembly\"\n", &reverset_asm},
	{"list", "list symbols/functions/flags\n", &reverset_list},
	{"/", "/ token\n", &reverset_strmod},
	{"hex", "hex num_bytes\n", &reverset_hex},
	{"quit", "quit\n", &reverset_quit}
};


#endif