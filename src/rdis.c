#include "rdis.h"

r_file* r_openfile(char * filename)
{
	r_file * file = r_file_init();

	FILE * f = fopen(filename, "r+");
	if (!f) {
		printf("Error opening file %s\n", filename);
		exit(1);
	}
	
	if (check_elf(f)) {
		elf_read_file(f, file);
	}

	file->file = f;
	//fclose(f);
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

	disassembler->recursive = 0;
	disassembler->overwrite = 0;

	disassembler->disassemble = NULL;

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

uint64_t r_disassemble_raw(r_disassembler * disassembler, unsigned char * raw_data, int size, int start_addr)
{
	r_disasm ** instructions = NULL;
	int num_instructions = 0;

	uint64_t laddr = start_addr;
	uint64_t lbyte = 0;
	int addr = start_addr;
	int iter = 0;
	while (iter < size) {
		r_disasm * disas = NULL;
		disas = disassembler->disassemble(raw_data + iter, addr+iter);
		laddr = disas->address;
		lbyte = disas->used_bytes;

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
	} else  {
		//Remove duplicates and merge
		int total_unique = disassembler->num_instructions + num_instructions;
		for (int i = 0; i < disassembler->num_instructions; i++) {
			int rm = 0;
			for (int j = 0; j < num_instructions; j++) {
				if (disassembler->instructions[i]->address == instructions[j]->address) {
					rm = 1;
					total_unique--;
				}
			}
			if (!rm && disassembler->instructions[i]->address >= addr && disassembler->instructions[i]->address < (laddr + lbyte))
				total_unique--;
		}
		r_disasm ** unique_instructions = malloc(sizeof(r_disasm*)*total_unique);
		int di = 0;
		int ni = 0;
		int i = 0;
		for (; i < total_unique; i++) {
			if (di < disassembler->num_instructions && ni < num_instructions) {
				if (disassembler->instructions[di]->address >= addr && disassembler->instructions[di]->address < (laddr + lbyte)) {
					i--;
					di++;
				} else if (disassembler->instructions[di]->address < instructions[ni]->address) {
					unique_instructions[i] = disassembler->instructions[di++];
					disassembler->instructions[di-1] = NULL;
				} else {
					unique_instructions[i] = instructions[ni++];
					instructions[ni-1] = NULL;
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
	return laddr;
}

void r_disassemble(r_disassembler * disassembler, r_file * file)
{
	uint64_t addr = 0;
	//If the end of the section is reached return
	while (disassembler->num_addresses > 0) {
		addr = r_disassembler_popaddr(disassembler);
		if (!disassembler->overwrite && r_disassembler_getbound(disassembler, addr) != -1) continue;

		rsection * section = r_file_section_addr(file, addr);
		if (!section) {
			continue;
		} else {
			printf("\rDisassembling %#lx\n", addr);
		}

		if (disassembler->overwrite) disassembler->overwrite = 0;
		int offset = addr - section->start;

		int tmp = disassembler->num_instructions;

		uint64_t laddr = r_disassemble_raw(disassembler, section->raw+offset, section->size - offset, section->start + offset);
		if ((disassembler->num_instructions - tmp) > 0) r_disassembler_addbound(disassembler, section->start + offset,  laddr);
	
		for (int i = tmp; i < disassembler->num_instructions; i++) {
			r_disasm * disasm = disassembler->instructions[i];
			for (int j = 0; j < disasm->metadata->num_addr; j++) {
				if (disasm->metadata->address_types[j] == META_ADDR_BRANCH && r_disassembler_getbound(disassembler, disasm->metadata->addresses[j]) == -1)
					r_disassembler_pushaddr(disassembler, disasm->metadata->addresses[j]);
			}
		}
	}

}

void r_disassembler_add_symbols(r_disassembler * disassembler, r_file * file)
{
	for (int i = 0; i < file->num_symbols; i++) {
		if (file->symbols[i].type == R_FUNC && file->symbols[i].addr64 != 0) {
			r_disassembler_pushaddr(disassembler, file->symbols[i].addr64);
		}
	}
}

void r_print_disas_f(r_disassembler * disassembler, uint64_t addr)
{
	for (int i = 0; i < disassembler->num_instructions; i++) {
		r_disasm * disas = disassembler->instructions[i];
		if (disas->address < addr) continue;
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
		//if (disas->metadata->type == r_tret) break;
	}
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
	if (!disassembler->overwrite) {
		for (int i = 0; i < disassembler->unum_addresses; i++) {
			if (disassembler->used_addrstack[i] == addr) return;
		}
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

	for (int i = 0; i < disassembler->unum_addresses; i++) {
		if (disassembler->used_addrstack[i] == addr) return addr;
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
	if (disassembler->num_bounds == 1) {
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

void r_disassembler_find_functions(r_disassembler * disassembler, r_file * file, r_cconv convention)
{
	switch (convention) {
		case rc_cdecl:

			break;
		case rc_unix64:
			break;
		default:
			printf("Only cdecl and unix64 calling conventions supported\n");
			return;
			break;
	}
}