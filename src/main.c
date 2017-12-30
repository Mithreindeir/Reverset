#include "disassembler.h"

int main(int argc, char ** argv)
{
	if (argc < 2) {
		printf("format: %s bytes\n", argv[0]);
		return 1;
	}
	disassemble_file(argv[1]);

	return 0;
}
