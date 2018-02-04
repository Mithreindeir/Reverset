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

//Removes whitespace 
char * no_space_strdup(char * str)
{
	int len2 = 0;
	int len = 0;
	while (str[len++]) {
		if (str[len] != ' ') len2++;
	}
	len2++;
	char * str2 = malloc(len2);
	for (int i = 0, j = 0; i < len && j < len2; i++) {
		if (str[i] != ' ')
			str2[j++] = str[i];
	}
	str2[len2] = 0;
	return str2;
}

//Version of strtok that fits my needs better
char * strtok_dup(char * string, char *delim, int last)
{
	static char * str = NULL;
	if (string)
		str = string;
	//For obtaining what is left in the str
	if (last) return strdup(str);
	int size = strlen(str);
	int i = 0;
	for (i = 0; i < size; i++) {
		if (!strncmp(str+i,delim,strlen(delim))) break;
	}
	if (i == size) {
		//str += i+1;
		return NULL;
	}
	char * str2 = malloc(i);
	for (int j = 0; j < i; j++) {
		str2[j] = str[j];
	}
	str2[i] = 0;
	str += i+1;
	return str2;
}