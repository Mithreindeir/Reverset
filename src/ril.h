#ifndef _RIL_H
#define _RIL_H

#include <stdio.h>
#include <stdlib.h>

/*
Reverset Low Level Intermediate Representation
Format:
mov eax, dword [eax] -> "eax := 32[eax]; rip := rip + (num bytes)"
add eax, dword [eax+ebx*4] -> "eax := eax + 32[eax+ebx*4]; rip := rip + (num bytes)"
jz 0x400400 -> "rip := rip + (num bytes);rip := zf ? 0x400400 : rip"

Tree:
mov eax, dword [eax+ebx*4]

		r_node_set
		/		  \
r_node_register	   r_node_memory
	/			    /		\
  eax			   32	r_node_add
						/		\
					  eax	   r_node_mul
				  				/		\
				  			  ebx		 4
*/

typedef struct r_node_t
{
	//TYPE 				  FORMAT 				//TREE TYPE
	r_node_register,	//reg_name 					leaf
	r_node_memory,		//size[expression]			leaf
	r_node_set,			//op1 = op2					branch
	r_node_add,			//op1 + op2					branch
	r_node_sub,			//op1 - op2					branch
	r_node_mul,			//op1 * op2					branch
	r_node_div			//op1 / op2					branch
} r_node_t;

typedef struct r_node
{
	char * tok;
	r_node_t type;
} r_node;




#endif