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

r_disassembler * r_disassembler_init()
{
	r_disassembler * disassembler = malloc(sizeof(r_disassembler));
	disassembler->instructions = NULL;
	disassembler->num_instructions = 0;

	disassembler->addrstack = NULL;
	disassembler->num_addresses = 0;

	disassembler->used_addrstack = NULL;
	disassembler->unum_addresses = 0;

	disassembler->bounds = NULL;
	disassembler->num_bounds = 0;

	disassembler->recursive = 1;

	return disassembler;
}

void r_disassembler_destroy(r_disassembler * disassembler)
{
	if (!disassembler) return;

	for (int i = 0; i < disassembler->num_instructions; i++) {
		r_disasm_destroy(disassembler->instructions[i]);
	}
	if (disassembler->instructions) free(disassembler->instructions);

	if (disassembler->addrstack) free(disassembler->addrstack);
	if (disassembler->used_addrstack) free(disassembler->used_addrstack);
	if (disassembler->bounds) free(disassembler->bounds);

	free(disassembler);
}

void r_disassemble_raw(r_disassembler * disassembler, r_disasm*(*disassemble)(unsigned char * stream, int address), unsigned char * raw_data, int size, int start_addr)
{
	r_disasm ** instructions = NULL;
	int num_instructions = 0;

	int addr = start_addr;
	int iter = 0;
	while (iter < size) {
		r_disasm * disas = NULL;
		disas = disassemble(raw_data + iter, addr+iter);
		if (!disas) break;
		iter += disas->used_bytes;
		num_instructions++;
		if (num_instructions == 1) {
			instructions = malloc(sizeof(r_disasm*));
		} else {
			instructions = realloc(instructions, sizeof(r_disasm*) * num_instructions);
		}
		instructions[num_instructions-1] = disas;
		if (disassembler->recursive && disas->metadata->type == r_tret) {
			break;
		}
	}
	//Merge arrays if existing, otherwise just set it
	if (disassembler->num_instructions == 0) {
		disassembler->instructions = instructions;
		disassembler->num_instructions = num_instructions;
	} else {
		//Remove duplicates and merge
		int total_unique = disassembler->num_instructions + num_instructions;
		for (int i = 0; i < disassembler->num_instructions; i++) {
			for (int j = 0; j < num_instructions; j++) {
				if (disassembler->instructions[i]->address == instructions[j]->address) total_unique--;
			}
		}
		r_disasm ** unique_instructions = malloc(sizeof(r_disasm*)*total_unique);
		int di = 0;
		int ni = 0;
		int i = 0;
		for (; i < total_unique; i++) {
			if (di < disassembler->num_instructions && ni < num_instructions) {
				if (disassembler->instructions[di]->address > instructions[ni]->address) {
					unique_instructions[i] = instructions[ni++];
					instructions[ni-1] = NULL;
				} else if (disassembler->instructions[di]->address < instructions[ni]->address) {
					unique_instructions[i] = disassembler->instructions[di++];
					disassembler->instructions[di-1] = NULL;
				} else {
					i--;
					ni++;
				}
			} else if (di < disassembler->num_instructions) {
				unique_instructions[i] = disassembler->instructions[di++];
				disassembler->instructions[di-1] = NULL;
			} else {
				unique_instructions[i] = instructions[ni++];
				instructions[ni-1] = NULL;
			}
		}

		for (int i = 0; i < disassembler->num_instructions; i++) {
			if (disassembler->instructions[i]) {
				r_disasm_destroy(disassembler->instructions[i]);
			}
		}
		free(disassembler->instructions);
		for (int i = 0; i < num_instructions; i++) {
			if (instructions[i]) {
				r_disasm_destroy(instructions[i]);
			}
		}
		free(instructions);

		disassembler->num_instructions = total_unique;
		disassembler->instructions = unique_instructions;
	}

}

r_disassembler * r_disassemble(rfile * file, r_disasm*(*disassemble)(unsigned char * stream, int address))
{
	r_disassembler * disassembler = r_disassembler_init();

	uint64_t addr = rfile_get_section(file, ".text")->start64;
	r_disassembler_pushaddr(disassembler, addr);

	while (disassembler->num_addresses > 0) {
		addr = r_disassembler_popaddr(disassembler);
		rsection * section = rfile_section_addr(file, addr);
		if (!section) {
			printf("Invalid section from address %#lx\n", addr);
			continue;
		}
		int offset = addr - section->start64;

		int tmp = disassembler->num_instructions;
		//void r_disassemble_raw(r_disassembler * disassembler, r_disasm*(*disassemble)(unsigned char * stream, int address), unsigned char * raw_data, int size, int start_addr)
		r_disassemble_raw(disassembler, disassemble, section->raw+offset, section->size - offset, section->start64 + offset);

		for (int i = tmp; i < disassembler->num_instructions; i++) {
			r_disasm * disasm = disassembler->instructions[i];
			for (int j = 0; j < disasm->metadata->num_addr; j++) {
				//printf("%#lx\n", disasm->metadata->addresses[j]);
				//getchar();
				r_disassembler_pushaddr(disassembler, disasm->metadata->addresses[j]);
			}
		}
	}

	return disassembler;
}

void r_print_disas(r_disassembler * disassembler)
{
	for (int i = 0; i < disassembler->num_instructions; i++) {
		r_disasm * disas = disassembler->instructions[i];
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

void r_disassembler_pushaddr(r_disassembler * disassembler, uint64_t addr)
{
	for (int i = 0; i < disassembler->num_addresses; i++) {
		if (disassembler->addrstack[i] == addr) return;
	}
	for (int i = 0; i < disassembler->unum_addresses; i++) {
		if (disassembler->used_addrstack[i] == addr) return;
	}
	
	disassembler->num_addresses++;
	if (disassembler->num_addresses == 1) {
		disassembler->addrstack = malloc(sizeof(uint64_t));
	} else {
		disassembler->addrstack = realloc(disassembler->addrstack, sizeof(uint64_t) * disassembler->num_addresses);
	}

	disassembler->addrstack[disassembler->num_addresses-1] = addr;
}

uint64_t r_disassembler_popaddr(r_disassembler * disassembler)
{
	if (disassembler->num_addresses <= 0) return 0;

	disassembler->num_addresses--;
	int addr = disassembler->addrstack[disassembler->num_addresses]; 
	if (disassembler->num_addresses == 0) {
		free(disassembler->addrstack);
		disassembler->addrstack = NULL;
	} else {
		disassembler->addrstack = realloc(disassembler->addrstack, sizeof(uint64_t) * disassembler->num_addresses);
	}

	disassembler->unum_addresses++;
	if (disassembler->unum_addresses == 1) {
		disassembler->used_addrstack = malloc(sizeof(uint64_t));
	} else {
		disassembler->used_addrstack = realloc(disassembler->used_addrstack, sizeof(uint64_t) * disassembler->unum_addresses);
	}
	disassembler->used_addrstack[disassembler->unum_addresses-1] = addr;

	return addr;
}

void r_disassembler_addbound(r_disassembler * disassembler, uint64_t s, uint64_t e)
{
	disassembler->num_bounds++;
	if (disassembler->num_bounds == 0) {
		disassembler->bounds = malloc(sizeof(block_bounds));
	} else {
		disassembler->bounds = realloc(disassembler->bounds, sizeof(block_bounds) * disassembler->num_bounds);
	}
	
	block_bounds bound;
	bound.start = s;
	bound.end = e;

	disassembler->bounds[disassembler->num_bounds-1] = bound; 
}

uint64_t r_disassembler_getbound(r_disassembler * disassembler, uint64_t addr)
{
	for (int i = 0; i < disassembler->num_bounds; i++) {
		if (disassembler->bounds[i].start <= addr && disassembler->bounds[i].end >= addr) return i;
	}

	return -1;
}