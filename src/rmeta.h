#ifndef _RMETA_H
#define _RMETA_H

#include "rtype.h"
#include <stdio.h>
#include <stdlib.h>

/*The context addresses are used in*/
#define META_ADDR_BOTH 2
#define META_ADDR_DATA 1
#define META_ADDR_BRANCH 0

/*Disassembly meta data
The r_disasm type is just for printing, but also contains metadata for analysis
Metadata includes the type of instruction, and any addresses referenced by the instruction.
It also includes an array to store xrefs for during later analysis, as well as comments.
All addresses are 64 bit so they can fit all.
*/

typedef enum r_meta_t
{
	r_tcjump,	/*Conditional Jump or branch instructions*/
	r_tujump,	/*Unconditional jump or branch*/
	r_tarith,	/*Arithmetic instructions*/
	r_tlogic,	/*Logical instructions*/
	r_tdata,	/*Data instruction (like mov or lea)*/
	r_tcall,	/*Call instruction*/
	r_tret,		/*Return from execution instruction*/
	r_tnone		/*Not determined, other, or none*/
} r_meta_t;


typedef struct r_meta
{
	char * comment;
	char * label;
	
	r64addr * addresses;
	char * address_types;
	int num_addr;


	r64addr * xref_to;
	int num_xrefto;

	r64addr * xref_from;
	int num_xreffrom;

	r_meta_t type;
} r_meta;

r_meta * r_meta_init();
void r_meta_add_addr(r_meta * meta, r64addr address, int type);
int r_meta_find_addr(r_meta * meta, r64addr address, int type);
void r_meta_destroy(r_meta * meta);

#endif