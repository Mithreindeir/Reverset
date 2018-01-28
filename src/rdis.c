#include "rdis.h"

rfile* r_openfile(char * filename)
{
	rfile * file = rfile_init();

	FILE * f = fopen(filename, "r");
	if (!f) {
		printf("Error opening file %s\n", filename);
		exit(1);
	}
	
	if (check_elf(f)) {
		elf_read_file(f, file);
	}

	fclose(f);
	return file;
}

r_disasm ** r_disassemble(rfile * file, r_disasm*(*disassemble)(unsigned char * stream, int address), int * num_disas)
{
	r_disasm ** disassembly = NULL;
	int num_disassembly = 0;

	rsection * text = rfile_get_section(file, ".text");
	if (text) {
		int addr = text->start32;
		int iter = 0;
		while (iter < text->size) {
			r_disasm * disas = NULL;
			disas = disassemble(text->raw + iter, addr+iter);
			if (!disas) break;
			iter += disas->used_bytes;
			num_disassembly++;
			if (num_disassembly == 1) {
				disassembly = malloc(sizeof(r_disasm*));
			} else {
				disassembly = realloc(disassembly, sizeof(r_disasm*) * num_disassembly);
			}
			disassembly[num_disassembly-1] = disas;
		}
	}
	*num_disas = num_disassembly;
	return disassembly;
}

void r_print_disas(r_disasm ** disassembly, int num_disassembly)
{
	for (int i = 0; i < num_disassembly; i++) {
		r_disasm * disas = disassembly[i];
		if (disas->metadata->label) printf("//\t%s\n", disas->metadata->label);
		printf("%#x:   ", disas->address);
		int b = 8*3;
		for (int i = 0; i < disas->used_bytes; i++) {
			if ((b-3) <= 0) {
				printf(".");
				break;
			} 
			printf("%02x ", disas->raw_bytes[i]);
			b -= 3;
		}
		while (b > 0) {
			printf("   ");
			b -= 3;
		}
		printf("\t");
		int space = 6-strlen(disas->mnemonic);
		printf("%s ", disas->mnemonic);
		for (int i = 0; i < space; i++) printf(" ");
		
		for (int i = 0; i < disas->num_operands; i++) {
			if (i!=0) printf(",");
			printf("%s", disas->op[i]);
		}
		if (disas->metadata->comment) printf("\t # %s", disas->metadata->comment);
		printf("\n");
	}	
}

r_disasm * r_disasm_init()
{
	r_disasm * disas = malloc(sizeof(r_disasm));
	disas->mnemonic = NULL;
	disas->num_operands = 0;
	disas->op[0] = NULL;
	disas->op[1] = NULL;
	disas->op[2] = NULL;
	disas->raw_bytes = NULL;
	disas->address = 0;
	disas->metadata = r_meta_init();

	return disas;
}

void r_disasm_destroy(r_disasm * disas)
{
	if (!disas) return;

	if (disas->mnemonic) free(disas->mnemonic);
	if (disas->op[0]) free(disas->op[0]);
	if (disas->op[1]) free(disas->op[1]);
	if (disas->op[2]) free(disas->op[2]);
	if (disas->raw_bytes) free(disas->raw_bytes);
	if (disas->metadata) r_meta_destroy(disas->metadata);

	free(disas);
}

