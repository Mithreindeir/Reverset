#include "rdis.h"

r_file* r_openfile(char * filename, char * perm)
{
	r_file * file = r_file_init();

	FILE * f = fopen(filename, perm);
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

	disassembler->linear = 0;
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

	//Copy bytes from section into buffer before use
	char buf[32];
	memset(buf, 0, 32);
	while (iter < size) {
		r_disasm * disas = NULL;
		memcpy(buf, raw_data + iter, (size-iter) >= 32 ? 32 : (size-iter));
		disas = disassembler->disassemble(buf, addr+iter);
		memset(buf, 0, 32);
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
		if (!disassembler->linear && disas->metadata->type == r_tret) {
			break;
		}
		//Also return if current instruction is a unconditional jump and cannot be skipped
		if (!disassembler->linear && disas->metadata->type == r_tujump) {
			//for (int i = 0; i < )
		}
	}
	//Merge arrays if existing, otherwise just set it
	if (disassembler->num_instructions == 0) {
		disassembler->instructions = instructions;
		disassembler->num_instructions = num_instructions;
	} else  {
		//Remove duplicates and merge
		/*
		int total_unique = disassembler->num_instructions + num_instructions;
		for (int i = 0; i < disassembler->num_instructions; i++) {
			r_disasm * disas1 = disassembler->instructions[i];
			if (disas1->address < start_addr) continue;
			if (disas1->address > laddr) break;
			int rm = 0;
			for (int j = 0; j < num_instructions; j++) {
				if (disas1->address == instructions[j]->address) {
					rm = 1;
					total_unique--;
				}
			}
			if (!rm && disassembler->instructions[i]->address >= addr && disassembler->instructions[i]->address < (laddr + lbyte))
				total_unique--;
		}*/
		int total_unique = disassembler->num_instructions + num_instructions;
		for (int i = 0; i < disassembler->num_instructions; i++) {
			r_disasm * disas1 = disassembler->instructions[i];
			if (disas1->address < start_addr) continue;

			if (disassembler->instructions[i]->address >= addr && disassembler->instructions[i]->address < (laddr + lbyte))
				total_unique--;

			if (disas1->address >= (laddr + lbyte)) break;

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
	int num_dis = 0;
	//If the end of the section is reached return
	while (disassembler->num_addresses > 0) {
		addr = r_disassembler_popaddr(disassembler);

		if (!disassembler->overwrite && r_disassembler_getbound(disassembler, addr) != -1) {
			continue;
		}
		rsection * section = r_file_section_addr(file, addr);
		if (!section) continue;
		if (!(R_EXEC&section->perm)) continue;
		int allowed  = !strncmp(section->name, ".text", 7);
		allowed = allowed || !strncmp(section->name, ".got", 3);
		allowed = allowed || !strncmp(section->name, ".plt", 3);
		if (!allowed) continue;
		clear_line();
		char progress[16];
		memset(progress, ' ', 15);
		float prg = (num_dis / (float)(1+num_dis+disassembler->num_addresses*2));
		for (int i = 0; i < (1+prg*15); i++) progress[i] = '#';
		progress[15] = 0;
		writef("\r[%s] Disassembling %s:[%#lx]", progress, section->name, addr);
		num_dis++;

		if (disassembler->overwrite) disassembler->overwrite = 0;
		int offset = addr - section->start;
		int tmp = disassembler->num_instructions;

		uint64_t laddr = r_disassemble_raw(disassembler, section->raw+offset, section->size - offset, section->start + offset);
		if ((disassembler->num_instructions - tmp) > 0) r_disassembler_addbound(disassembler, section->start + offset,  laddr);

		if (!disassembler->recursive) break;
		for (int i = 0; i < disassembler->num_instructions; i++) {
			r_disasm * disasm = disassembler->instructions[i];
			if (disasm->address < (section->start + offset)) continue;
			if (disasm->address > laddr) break;
			for (int j = 0; j < disasm->metadata->num_addr; j++) {
				if (r_disassembler_getbound(disassembler, disasm->metadata->addresses[j]) == -1)
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
