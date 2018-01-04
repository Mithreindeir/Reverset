#include "disassembler.h"


void disassemble_file(char * filename, unsigned int args, char * symbol_start, int start_addr)
{
	elf_file * elf = read_elf(filename);

	disassembler * disas = malloc(sizeof(disassembler));
	disas->instructions = NULL;
	disas->num_instructions = 0;
	disas->format = NULL;
	disas->num_addresses = 0;
	disas->addrstack = NULL;
	disas->unum_addresses = 0;
	disas->used_addrstack = NULL;
	disas->bounds = NULL;
	disas->num_bounds = 0;
	//Args = 00 00 00 00 
	//linear  ^
	//print all  ^
	//recursive     ^
	disas->linear = (args & 0x40) != 0;
	disas->printall = (args & 0x10) != 0;
	disas->recursive = (args & 0x04) != 0;
	//Temporarily before recursive disas is done
	disas->printall = disas->recursive ? 1 : disas->printall;


	int ie = elf->entry_point;
	if (symbol_start != NULL) {
		int fail = 0;
		if (!!strncmp(symbol_start, "sym.", 4)) {
			fail = 1;
		} else {
			int tmpaddr = elf_get_symbol(elf, symbol_start+4);
			if (tmpaddr == -1) {
				fail = 1;
			} else {
				ie = tmpaddr;
			}
		}

		if (fail) printf("Symbol %s not found. Defaulting to elf entry point (Did you preface symbol with 'sym.'?)\n", symbol_start);
	}
	if (start_addr != -1) ie = start_addr;

	if (disas->recursive) disassemble_recursive(disas, elf, ie);
	else {
		elf_section_data * text = elf_get_section(elf, ".text");
		elf_section_data * data = elf_get_section(elf, ".rodata");
		int off = ie - text->addr;

		if ((off > text->size) || (off < 0)) {
			printf("Start address given not inside .text section\n");
			exit(1);
		}
		disassemble(disas, text->data + off, text->size-off, ie);
	}
	disassemble_analyze(disas, elf);
	disassemble_print(disas, elf);

	disassembler_destroy(disas);

	//Free elf file 
}

void disassemble_pushaddr(disassembler * disas, int addr)
{
	for (int i = 0; i < disas->num_addresses; i++) {
		if (addr == disas->addrstack[i]) {
			return;
		}
	}
	for (int i = 0; i < disas->unum_addresses; i++) {
		if (addr == disas->used_addrstack[i]) {
			return;
		}
	}
	disas->num_addresses++;
	if (disas->num_addresses == 1) {
		disas->addrstack = malloc(sizeof(int));
	} else {
		disas->addrstack = realloc(disas->addrstack, sizeof(int) * disas->num_addresses);
	}
	disas->addrstack[disas->num_addresses-1] = addr;
}

int disassemble_popaddr(disassembler * disas)
{
	if (disas->num_addresses <= 0) return 0;
	disas->num_addresses--;
	int addr = disas->addrstack[disas->num_addresses];
	if (disas->num_addresses == 0) {
		free(disas->addrstack);
		disas->addrstack = NULL;
	} else {
		disas->addrstack = realloc(disas->addrstack, sizeof(int) * disas->num_addresses);
	}
	disas->unum_addresses++;
	if (disas->unum_addresses == 1) {
		disas->used_addrstack = malloc(sizeof(int));
	} else {
		disas->used_addrstack = realloc(disas->used_addrstack, sizeof(int) * disas->unum_addresses);
	}
	disas->used_addrstack[disas->unum_addresses-1] = addr;
	return addr;
}

void disassemble_addbound(disassembler * disas, int start_addr, int end_addr)
{
	disas->num_bounds++;
	if (disas->num_bounds == 1) {
		disas->bounds = malloc(sizeof(function_bounds));
	} else {
		disas->bounds = realloc(disas->bounds, sizeof(function_bounds) * disas->num_bounds);
	}
	function_bounds bound;
	bound.start_addr = start_addr;
	bound.end_addr = end_addr;
	disas->bounds[disas->num_bounds-1] = bound;
}

int disassemble_getbound(disassembler * disas, int addr)
{
	for (int i = 0; i < disas->num_bounds; i++) {
		if (disas->bounds[i].start_addr <= addr && disas->bounds[i].end_addr >= addr) return i;
	}
	
	return -1;
}

void disassemble(disassembler * disas, unsigned char * raw_data, int size, int start_addr)
{
	int b = 0;
	x86_instruction ** instructions = malloc(sizeof(x86_instruction*));
	int num_instructions = 1;
	x86_instruction * ci = NULL;
	int jump_instr = 0;
	int functions = 3;
	while(1) {
		ci = x86_decode_instruction(raw_data + b, size);
		ci->address = b+start_addr;
		x86_resolve_address(ci, b+start_addr);

		b += ci->used_bytes;
		instructions[num_instructions-1] = ci;
		if (b >= size) {
			break;
		}
		if (ci->mnemonic[0] == 'j') {
			int tmp = 0;
			if (ci->op1.type == REL1632) {
				tmp = ci->op1.rel1632;
				tmp = tmp < 0x80000000 ? tmp : 0x100000000-tmp;
			} else if (ci->op1.type == REL8) {
				tmp = ci->op1.rel8;
				tmp = tmp < 0x80 ? tmp : 0x100 - tmp;
			}
			jump_instr = jump_instr > tmp ? jump_instr : tmp;
		}
		if (disas->recursive && !strcmp(ci->mnemonic, "ret")) {
			//Check if can be skipped
			break;
		}
		num_instructions++;
		instructions = realloc(instructions, num_instructions * sizeof(x86_instruction*));
	}
	if (disas->num_instructions == 0) {
		disas->instructions = instructions;
		disas->num_instructions = num_instructions;
	} else {
		//Merge both arrays and remove duplicates, keeping the ones in the old array
		int total_unique = disas->num_instructions + num_instructions;
		for (int i = 0; i < disas->num_instructions; i++) {
			for (int j = 0; j < num_instructions; j++) {
				if (disas->instructions[i]->address == instructions[j]->address) total_unique--;
			}
		}
		x86_instruction ** instr = malloc(sizeof(x86_instruction*)*(total_unique));
		int di = 0;
		int ni = 0;
		int i = 0;
		for (; i < total_unique; i++) {
			if (di < disas->num_instructions && ni < num_instructions) {
				if (disas->instructions[di]->address > instructions[ni]->address) {
					instr[i] = instructions[ni++];
				} else if (disas->instructions[di]->address < instructions[ni]->address) {
					instr[i] = disas->instructions[di++];
				} else {
					i--;
					ni++;
				}
			} else if (di < disas->num_instructions) {
				instr[i] = disas->instructions[di++];
			} else instr[i] = instructions[ni++];
		}

		free(disas->instructions);
		free(instructions);

		disas->num_instructions = total_unique;
		disas->instructions = instr;
	}
}

void disassemble_recursive(disassembler * disas, elf_file * file, int start_addr)
{
	/*Todo handle relocs so that the recursion can propogate */

	char * sec_name = NULL;
	elf_section_data * sec = NULL;
	//0x804842c
	int addr = start_addr;
	disassemble_pushaddr(disas, addr);

	while (disas->num_addresses > 0) {
		int addr = disassemble_popaddr(disas);
		sec_name = elf_find_section(file, addr);
		if (!sec_name) {
			printf("Elf entry point invalid\n");
			continue;
			exit(1);
		}
		sec = elf_get_section(file, sec_name);
		if (!sec) {
			printf("This should never happen ¯\\_(ツ)_/¯ \n");
			exit(1);
		}
		int off = addr - sec->addr;
		//printf("Section %s and addr %#x with start %#x\n", sec->name, addr, sec->addr);
		//getchar();
		//if (!!strcmp(".text", sec->name)) continue;
		int tmp = disas->num_instructions;
		disassemble(disas, sec->data+off, sec->size-off, sec->addr+off);
		if (disas->num_instructions > 0) disassemble_addbound(disas, addr, disas->instructions[disas->num_instructions-1]->address+disas->instructions[disas->num_instructions-1]->used_bytes);
		x86_instruction * ci = NULL;
		for (int i = tmp; i < disas->num_instructions; i++) {
			ci = disas->instructions[i];
			//if (!!strcmp(ci->mnemonic, "call")) continue;
			if (ci->op1.type == REL1632 && disassemble_getbound(disas, ci->op1.rel1632) == -1) {
				disassemble_pushaddr(disas, ci->op1.rel1632);
			}
			if (ci->op2.type == REL1632 && disassemble_getbound(disas, ci->op1.rel1632) == -1) {
				disassemble_pushaddr(disas, ci->op2.rel1632);
			}
		}
	}
}

void disassemble_analyze(disassembler * disas, elf_file * elf)
{
	//Resolving relative addresses and symbols
	int entry_point = elf->entry_point;
	formatter * format = formatter_init(disas->instructions, disas->num_instructions);
	formatter_analyze(format, entry_point, disas->instructions, disas->num_instructions, elf);
	disas->format = format;
}

void disassemble_print(disassembler * disas, elf_file * elf)
{
	int addr = 0;
	x86_instruction * ci = NULL;
	char * last_section = NULL;
	for (int i = 0; i < disas->num_instructions; i++) {
		ci = disas->instructions[i];
		char * new_section = elf_find_section(elf, ci->address);
		if (!last_section || !!strcmp(new_section, last_section)) {
			printf("//\tSECTION: %s\n", new_section);

			last_section = new_section;
		}
		formatter_precomment(disas->format, ci->address);
		
		addr += ci->used_bytes;
		printf("%#08x\t", ci->address);
		int max_bytes = 3*8;
		for (int i = 0; i < ci->used_bytes; i++) {
			if ((max_bytes - 3) <= 0) {
				printf(".  ");
				max_bytes -= 3;
				break;
			}
			printf("%02x ", ci->bytes[i]);
			max_bytes -= 3;
		}
		while (max_bytes > 0) {
			max_bytes -= 3;
			printf("   ");
		}
		formatter_printjump(disas->format, ci->address);
		print_instruction(ci);
		formatter_postcomment(disas->format,  ci->address);
		printf("\n");
		if (!disas->printall && ci->mnemonic[0] == 'r') break;
	}
}

void disassemble_print_recursive(disassembler * disas, int func_number)
{

}

void disassembler_destroy(disassembler * disas)
{
	if (!disas) return;

	for (int i = 0; i < disas->num_instructions; i++) {
		free(disas->instructions[i]);
	}
	if (disas->instructions) free(disas->instructions);
	if (disas->format) formatter_destroy(disas->format);
	if (disas->bounds) free(disas->bounds);
	if (disas->used_addrstack) free(disas->used_addrstack);
	if (disas->addrstack) free(disas->addrstack);

	free(disas);
}
