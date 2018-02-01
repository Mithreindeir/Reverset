#include <stdio.h>
#include <stdlib.h>

#include "rfile.h"
#include "rdis.h"
#include "ranal.h"
#include "arch/x86/x86disassembler.h"
#include "arch/x86_64/x64assembler.h"
#include "arch/x86_64/x64disassembler.h"
//48 2d 38 10 60 00
static r_disasm*(*disassemblers[])(unsigned char * stream, int address) = {NULL, x86_decode_instruction, x64_decode_instruction, NULL};

int main(int argc, char ** argv)
{
	/*
	if (argc < 2) {
		printf("Usage: %s \"asm\"\n", argv[0]);
		return 1;
	}
	x64_assemble(argv[1]);

	return 0;
	*/
	if (argc < 2) {
		printf("Usage: %s file\n", argv[0]);
		return 1;
	}

	r_file * file = r_openfile(argv[1]);
	r_file_find_strings(file);
	r_disassembler *  disassembler = r_disassembler_init();
	r_analyzer * anal = r_analyzer_init();
	if (disassemblers[file->arch] != NULL) {
		disassembler->disassemble =  disassemblers[file->arch];
		r_disassembler_pushaddr(disassembler,  r_file_get_section(file, ".text")->start64);
		r_disassembler_add_symbols(disassembler, file);
		r_disassemble(disassembler, file);
		r_meta_analyze(anal, disassembler, file);
	} else {
		printf("Architecture not supported\n");
		return 1;
	}
	uint64_t current_address = file->entry_point;

	uint64_t * addresses = malloc(sizeof(uint64_t));
	addresses[0] = current_address;
	int num_addresses = 1;

	int run = 1;
	while (run) {
		printf("%#lx>", current_address);
		char buf[256];
		memset(buf, 0, 256);
		scanf("%256s", buf);
		int size = strlen(buf);
		int iter = 0;
		while (iter < size) {
			if (buf[iter] == ' ') continue;
			else if (buf[iter] == 'd') {
				//r_disassemble_address(disassembler, file, current_address);
				//r_meta_analyze(anal, disassembler, file);
			} else if (buf[iter]=='0' && buf[iter+1] == 'x') {
				char buf2[16];
				memset(buf2, 0, 16);
				buf2[0] = '0';
				buf2[1] = 'x';
				int i = 0;
				for (i = 2; i < 9 && (iter+i) < size; i++) {
					if ((buf[iter+i] >= 0x30 && buf[iter+i] < 0x40) || (buf[iter+i] >= 'a' && buf[iter+i] <= 'f'))
						buf2[i] = buf[iter+i];
					else break;
				}
				int len = 0;
				if (r_meta_isaddr(buf2, &len)) {
					current_address = (uint64_t)strtol(buf2, NULL, 0);
					num_addresses++;
					addresses = realloc(addresses, sizeof(uint64_t) * num_addresses);
					addresses[num_addresses-1] = current_address;
				}
				iter += i-1;
			} else if (buf[iter]=='p'){
				r_meta_printall(disassembler, anal,current_address);
			} else if (buf[iter] == 'q') {
				run = 0;
				break;
			} else if (buf[iter] == 'b') {
				if (num_addresses > 1) {
					num_addresses--;
					addresses = realloc(addresses, sizeof(uint64_t) * num_addresses);
				}
				current_address = addresses[num_addresses-1];
			} else {
				printf("%c invalid\n", buf[iter]);
				break;
			}
			iter++;
		}
	}

	r_disassembler_destroy(disassembler);
	r_file_destroy(file);
	r_analyzer_destroy(anal);

	return 0;
}