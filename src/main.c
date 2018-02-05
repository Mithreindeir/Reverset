#include <stdio.h>
#include <stdlib.h>

#include "rfile.h"
#include "rdis.h"
#include "ranal.h"
#include "arch/x86/x86disassembler.h"
#include "arch/x86_64/x64assembler.h"
#include "arch/x86_64/x64disassembler.h"
#include "reverset.h"

//48 2d 38 10 60 00

int main(int argc, char ** argv)
{
	if (argc < 2) {
		printf("Usage: %s file\n", argv[0]);
		return 1;
	}
	reverset * rev = reverset_init();
	reverset_openfile(rev, argv[1]);
	reverset_sh(rev);

	reverset_destroy(rev);
	return 0;
}