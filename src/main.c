#include "disassembler.h"

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
	for (int i = 1; i < argc; i++) {
		if (argv[i][0] == '-') {
			char arg = argv[i][1];
			int size = strlen(argv[i]);
			for (int j = 1; j < size; j++) {
				arg = argv[i][j];
				if (arg == 'h') {
					printf("Reverset: A disassembly and binary analysis tool\n");
					printf("Usage: %s args file\n", argv[0]);
					printf("Args:\n-h for help\n");
					printf("-r for recursive descent disassembly\n");
					printf("-l for linear sweep disassembly\n");
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
		} else if (idx == 1) {
			idx = i;
		} else {
			printf("Incorrect arguments\n");
			printf("Use -h for help\n");
		}
	}
	if (args != 0 && idx == 1) {
		printf("No input file specified\n");
		return 1;
	}
	disassemble_file(argv[idx], args);

	return 0;
}
