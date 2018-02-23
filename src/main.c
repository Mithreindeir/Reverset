#include <stdio.h>
#include <stdlib.h>

#include "rfile.h"
#include "rdis.h"
#include "ranal.h"
#include "arch/x86/x86disassembler.h"
#include "arch/x86_64/x64assembler.h"
#include "arch/x86_64/x64disassembler.h"
#include "reverset.h"

int main(int argc, char ** argv)
{
	char * file = NULL;
	int write = 0;

	for (int i = 1; i < argc; i++) {
		if (argv[i][0] == '-') {
			int len = strlen(argv[i]);
			for (int j = 1; j < len; j++) {
				switch (argv[i][j]) {
					case 'w':
						write = 1;
						break;
					case 'h':
						printf("Reverset: Reverse engineering and Binary Analysis Tool\n");
						printf("Usage: %s file options\n", argv[0]);
						printf("Option: -h for help\n");
						printf("Option: -w to open the file with write permissions\n");
						break;
				}
			}
		} else if (!file) {
			file = argv[i];
		} else {
			printf("Unwanted parameter: %s\n", argv[i]);
		}
	}
	char perm[] = "r+";
	if (!write) perm[1] = 0;

	if (file) {
		reverset * rev = reverset_init();
		reverset_openfile(rev, file, perm);
		reverset_sh(rev);

		reverset_destroy(rev);
	}
	return 0;
}
