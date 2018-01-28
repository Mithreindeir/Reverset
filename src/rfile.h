#ifndef _RFILE_H
#define _RFILE_H

#include "rtype.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*Generic file type*/

typedef enum rarchitecture
{
	r_noarch,
	r_x86,
	r_x86_64,
	r_arm
} rarchitecture;

typedef enum rsym_t
{
	R_NONE,
	R_FUNC,
	R_OBJECT,
	R_ARRAY,
	R_STRING
} rsym_t;

typedef struct rsymbol
{
	char * name;
	union {
		r32addr addr32;
		r64addr addr64;
	};
	rsym_t type;
} rsymbol;

typedef struct rstring
{
	char * string;
	union {
		r32addr addr32;
		r64addr addr64;
	};
} rstring;

typedef enum rsection_t
{
	r_notype,
	r_programdefined,
	r_symboltab,
	r_stringtab,
	r_other
} rsection_t;


typedef struct rsection
{
	char * name;
	unsigned char * raw;
	int size;
	rsection_t type;
	union {
		r32addr start32;
		r64addr start64;
	};
} rsection;

typedef struct rfile
{
	//1 for 32 2 for 64
	int bits;
	rsymbol * symbols;
	int num_symbols;

	rstring * strings;
	int num_strings;

	rsection * sections;
	int num_sections;

	char * raw_file;
	int size;

	r64addr entry_point;
	rarchitecture arch;
} rfile;

rfile * rfile_init();
rfile * rfile_read(char * filename);
void rfile_destroy(rfile * file);
rsection * rfile_get_section(rfile * file, char * name);
void rfile_find_strings(rfile * file);

#endif