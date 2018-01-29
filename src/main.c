#include <stdio.h>
#include <stdlib.h>

#include "rfile.h"
#include "rdis.h"
#include "ranal.h"
#include "arch/x86/x86disassembler.h"
#include "arch/x86_64/x64disassembler.h"
//48 2d 38 10 60 00
static unsigned char bytes[] = {0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00};

static r_disasm*(*disassemblers[])(unsigned char * stream, int address) = {NULL, x86_decode_instruction, x64_decode_instruction, NULL};

int main(int argc, char ** argv)
{
	if (argc < 2) {
		printf("Usage: %s file\n", argv[0]);
		return 1;
	}

	rfile * file = r_openfile(argv[1]);
	rfile_find_strings(file);
	if (disassemblers[file->arch] != NULL) {
		r_disassembler * disassembler = r_disassemble(file, disassemblers[file->arch]);
		r_meta_analyze(disassembler->instructions, disassembler->num_instructions, file);
		r_print_disas(disassembler);

		r_disassembler_destroy(disassembler);
	} else {
		printf("Architecture not supported\n");
		return 1;
	}
	
	//disassemble_file(argv[idx], args, sym_s, start_addr);

	return 0;
}