#ifndef _REVERSET_H
#define _REVERSET_H

#include <stdio.h>
#include <stdlib.h>

#include "rfile.h"
#include "rdis.h"
#include "ranal.h"
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
	char * pipe;
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
} reverset;

typedef struct r_cmd
{
	char * name;
	int argc;
	char * usage;
	char*(*execute)(reverset * rev, char ** args);
} r_cmd;

/*Public API*/
reverset * reverset_init();
void reverset_destroy(reverset * rev);

void reverset_openfile(reverset * rev, char * file);
char * reverset_execute(reverset * rev, char * cmd);
char * reverset_eval(reverset * rev, int argc, char ** argv);
void reverset_sh(reverset * rev);

/*Private Functions for reverset shell*/
char * reverset_readline();
char ** reverset_split_line(char * line, int * num_args);
char * reverset_split(char * first);

/*Wrapper functions*/
uint64_t reverset_resolve_arg(reverset * rev, char * arg);
char* reverset_analyze(reverset * rev, char ** args);
char* reverset_print(reverset * rev, char ** args);
char* reverset_disas(reverset * rev, char ** args);
char* reverset_write(reverset * rev, char ** args);
char* reverset_goto(reverset * rev, char ** args);
char * reverset_asm(reverset * rev, char ** args);
char * reverset_quit(reverset * rev, char ** args);
char * reverset_list(reverset * rev, char ** args);

const static r_cmd r_commands[] = {
	{"print", 1, "print all/here/function/address\n", &reverset_print},
	{"anal", 1, "anal here/function/address\n", &reverset_analyze},
	{"disas", 1, "disas here/function/address\n", &reverset_disas},
	{"write", 1, "write \"bytes\"\n", &reverset_write},
	{"goto", 1, "goto address/symbol\n", &reverset_goto},
	{"asm", 1, "asm \"assembly\"\n", &reverset_asm},
	{"list", 1, "list symbols/functions/flags\n", &reverset_list},
	{"quit", 0, "quit\n", &reverset_quit}
};


#endif