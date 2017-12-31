#include "disassembler.h"


void disassemble_file(char * filename, unsigned int args)
{
	elf_file * elf = read_elf(filename);
	elf_section_data * text = elf_get_section(elf, ".text");

	disassembler * disas = malloc(sizeof(disassembler));
	disas->instructions = NULL;
	disas->num_instructions = 0;
	disas->format = NULL;
	//Args = 00 00 00 00 
	//linear  ^
	//print all  ^
	//recursive     ^
	disas->linear = (args & 0x40) != 0;
	disas->printall = (args & 0x10) != 0;
	disas->recursive = (args & 0x04) != 0;

	disassemble(disas, text->data, text->size);
	disassemble_analyze(disas, elf);
	disassemble_print(disas, elf->entry_point);

	disassembler_destroy(disas);
}


void disassemble(disassembler * disas, unsigned char * raw_data, int size)
{
	int b = 0;
	x86_instruction ** instructions = malloc(sizeof(x86_instruction*));
	int num_instructions = 1;
	x86_instruction * ci = NULL;
	int jump_instr = 0;
	int functions = 3;
	while(1) {
		ci = x86_decode_instruction(raw_data + b, size);

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
		if (disas->recursive && !strcmp(ci->mnemonic, "ret") && jump_instr < b) {
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
		disas->instructions = realloc(disas->instructions, sizeof(x86_instruction *)* (num_instructions+ disas->num_instructions));
		for (int i = 0; i < num_instructions; i++) {
			disas->instructions[i+disas->num_instructions] = instructions[i]; 
			disas->num_instructions++;
		}

		free(instructions);
	}
}

void disassemble_analyze(disassembler * disas, elf_file * elf)
{
	//Resolving relative addresses and symbols
	int entry_point = elf->entry_point;
	int addr = elf->entry_point;
	x86_instruction * ci = NULL;
	for (int i = 0; i < disas->num_instructions; i++) {
		x86_resolve_address(disas->instructions[i], addr);
		addr += disas->instructions[i]->used_bytes;
	}
	formatter * format = formatter_init(entry_point, disas->instructions, disas->num_instructions);
	formatter_analyze(format, entry_point, disas->instructions, disas->num_instructions, elf);
	disas->format = format;
}

void disassemble_print(disassembler * disas, int entry_point)
{
	int addr = 0;
	x86_instruction * ci = NULL;
	for (int i = 0; i < disas->num_instructions; i++) {
		printf("%#08x\t", addr+entry_point);
		ci = disas->instructions[i];
		addr += ci->used_bytes;
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
		formatter_printjump(disas->format, addr+entry_point - ci->used_bytes);
		print_instruction(ci);
		formatter_printcomment(disas->format, addr+entry_point-ci->used_bytes);
		printf("\n");
	}
}

void disassembler_destroy(disassembler * disas)
{
	if (!disas) return;

	for (int i = 0; i < disas->num_instructions; i++) {
		free(disas->instructions[i]);
	}
	if (disas->instructions) free(disas->instructions);
	if (disas->format) formatter_destroy(disas->format);

	free(disas);
}