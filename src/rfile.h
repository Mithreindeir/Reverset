#ifndef _r_file_H
#define _r_file_H

#include "rtype.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*Generic file type*/

//Set bit if the symbol is a reloc
#define R_RELOCBIT 0x80
#define R_RELOC(v) (v & R_RELOCBIT)
//Permissions
#define R_EXEC 0x1
#define R_WRITE 0x2
#define R_READ 0x4

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
	R_STRING,
} rsym_t;

typedef struct rsymbol
{
	char * name;
	uint64_t addr64;
	rsym_t type;
} rsymbol;

typedef struct rstring
{
	int len;
	char * string;
	int section;
	uint64_t addr64;
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
	//Offset is the offset in the raw file
	char * name;
	unsigned char * raw;
	int size;
	long offset;

	rsection_t type;
	uint64_t start;
	int perm;

} rsection;

typedef struct r_file
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

	FILE * file;

	r64addr entry_point;
	rarchitecture arch;
} r_file;

r_file * r_file_init();
r_file * r_file_read(char * filename);
void r_file_destroy(r_file * file);
rsection * r_file_get_section(r_file * file, char * name);
void r_file_find_strings(r_file * file);

void r_file_patch(r_file * file, uint64_t addr, unsigned char * bytes, int num_bytes);
//Returns the section that contains addr
rsection * r_file_section_addr(r_file * file, uint64_t addr);
rstring * r_file_in_string(r_file * file, uint64_t addr);

#endif