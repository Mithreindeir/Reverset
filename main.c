#include "disas.h"
#include "parse_elf.h"

int main(int argc, char ** argv)
{
	if (argc < 2) {
		printf("format: %s bytes\n", argv[0]);
		return 1;
	}
	int dev = 1;
	unsigned char * buffer;
	unsigned int size = 0;
	elf_file * elf;
	if (dev) {
		elf = read_elf(argv[1]);
		int section = -1;
		for (int i = 0; i < elf->num_sections; i++) {
			if (!strncmp(".text", elf->sections[i]->name, 5)) {
				section = i;
				break;
			}
		}
		if (section == -1) {
			printf("NO .text section\n");
			return 1;
		}
		buffer = elf->sections[section]->data;
		size = elf->sections[section]->size;
		printf("Section: %s\n", elf->sections[section]->name);

	} else {
		buffer = malloc(255);
		int size = strlen(argv[1]);

		if (size > 255) {
			printf("Input too long\n");
		}
		memset(buffer, 0x00, 255);
		string_to_hex(argv[1], buffer);
	}
	//int size = strlen(argv[1]);

	//if (size > 255) {
	//	printf("Input too long\n");
	//}
	//memset(buffer, 0x00, 255);
	//string_to_hex(argv[1], buffer);
	int b = 0;
	x86_instruction ** instructions = malloc(sizeof(x86_instruction*));
	int num_instructions = 1;
	x86_instruction * ci = NULL;
	while(1) {
		if (dev) printf("%#08x\t", b+elf->entry_point);
		ci = x86_decode_instruction(buffer + b, size);
		b += ci->used_bytes;
		//printf("%d bytes\t", ci->used_bytes);
		int max_bytes = 3*8;
		for (int i = 0; i < ci->used_bytes; i++) {
			printf("%02x ", buffer[b-ci->used_bytes+i]);
			max_bytes -= 3;
		}
		//Align all instructions
		while (max_bytes > 0) {
			max_bytes -= 3;
			printf("   ");
		}
		printf("\t");
		print_instruction(ci);
		//printf("\n");
		
		instructions[num_instructions-1] = ci;
		num_instructions++;
		instructions = realloc(instructions, num_instructions * sizeof(x86_instruction*));
		if (b >= size/2) {
			break;
		}
		printf(RESET);
		printf("\n");

		if (!strcmp("non", ci->mnemonic) || !strcmp("ret", ci->mnemonic)) getchar();
	}
	printf("\n");
	printf(RESET);
	//free(elf);

	return 0;
}
