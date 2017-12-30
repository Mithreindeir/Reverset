#include "disassembler.h"


void disassemble_file(char * filename)
{
	elf_file * elf = read_elf(filename);
	elf_section_data * text = elf_get_section(elf, ".text");

	disassembler * disas = malloc(sizeof(disassembler));
	disas->raw_data = text->data;
	disas->size = text->size;
	disas->instructions = NULL;
	disas->num_instructions = 0;
	disas->format = NULL;

	disassemble(disas);
	disassemble_analyze(disas, elf);
	disassemble_print(disas, elf->entry_point);

	disassembler_destroy(disas);
}


void disassemble(disassembler * disas)
{
	int b = 0;
	x86_instruction ** instructions = malloc(sizeof(x86_instruction*));
	int num_instructions = 1;
	x86_instruction * ci = NULL;
	while(1) {
		ci = x86_decode_instruction(disas->raw_data + b, disas->size);
		b += ci->used_bytes;
		instructions[num_instructions-1] = ci;
		if (b >= disas->size) {
			break;
		}
		num_instructions++;
		instructions = realloc(instructions, num_instructions * sizeof(x86_instruction*));
	}
	disas->instructions = instructions;
	disas->num_instructions = num_instructions;
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
			printf("%02x ", disas->raw_data[addr-ci->used_bytes+i]);
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
	if (disas->raw_data) free(disas->raw_data);

	free(disas);
}