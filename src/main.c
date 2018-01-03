#include "disassembler.h"
#include <string.h>

int main(int argc, char ** argv)
{
	if (argc < 2) {
		printf("format: %s args file\n", argv[0]);
		return 1;
	}
	/*
	disas->linear = (args & 0x40) != 0;
	disas->printall = (args & 0x10) != 0;
	disas->recursive = (args & 0x04) != 0;
	*/
	int args = 0;
	int idx = 1;
	char * sym_s = NULL;
	char last_arg = 0;
	int start_addr = -1;
	for (int i = 1; i < argc; i++) {
		if (argv[i][0] == '-') {
			char arg = argv[i][1];
			int size = strlen(argv[i]);
			for (int j = 1; j < size; j++) {
				arg = argv[i][j];
				last_arg = arg;
				if (arg == 'h') {
					printf("Reverset: A disassembly and binary analysis tool\n");
					printf("Usage: %s args file\n", argv[0]);
					printf("Args:\n-h for help\n");
					printf("-r for recursive descent disassembly\n");
					printf("-l for linear sweep disassembly\n");
					printf("-f to specify a symbol to start disassembly at. (default is program entry point)\n");
					printf("-a to specify an address to start disassembly at. (default is program entry point)\n");
					printf("-p to print all disassembled instructions\n");
					return 1;
				} else if (arg == 'r') {
					printf("Recusive descent is still under construction\n");
					args |= 0x04;
				} else if (arg == 'l') {
					args |= 0x40;
				} else if (arg == 'p') {
					args |= 0x10;
				}
			}
		} else if (idx == 1 && last_arg != 's' && last_arg != 'a') {
			idx = i;
		} else if (last_arg == 's') {
			sym_s = argv[i];
			last_arg = 0;
		} else if (last_arg == 'a') {
			int s = strlen(argv[i]);
			int b = 16;
			if (s > 2) {
				if (argv[i][0] == '0' && argv[i][1] == 'x') b = 0;
			}
			start_addr = strtol(argv[i], NULL, b);
			last_arg = 0;
			} else {
			printf("Incorrect arguments\n");
			printf("Use -h for help\n");
		}
	}
	if (args != 0 && idx == 1) {
		printf("No input file specified\n");
		return 1;
	}
	if (sym_s) printf("start at: %s\n", sym_s);
	disassemble_file(argv[idx], args, sym_s, start_addr);

	return 0;
}
