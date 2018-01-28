#include "x86common.h"

char * x64_get_register(int r, int size, int rexb)
{
	int index = 4*r + size-1 + rexb * 32;
	return x64_general_registers[index];
}

char * x86_get_register(int r, int size)
{
	int index = 4*r + size-1;
	return x64_general_registers[index];
}

r_meta_t instr_type(char * mnemonic)
{
	for (int i = 0; i < (sizeof(instr_pairs)/sizeof(instr_pair)); i++) {
		if (!strcmp(mnemonic, instr_pairs[i].mnemonic)){
			return instr_pairs[i].type;
		} 
	}

	return r_tnone;
}