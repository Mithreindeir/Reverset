#include <stdio.h>
#include <stdlib.h>

#include "rfile.h"
#include "rdis.h"
#include "ranal.h"
#include "arch/x86_64/x64lift.h"
#include "arch/x86/x86disassembler.h"
#include "arch/x86_64/x64assembler.h"
#include "arch/x86_64/x64disassembler.h"
#include "reverset.h"

void print_help(char * name)
{
	printf("Reverset: Reverse Engineering and Binary Analysis Tool\n");
	printf("Usage: %s file options\n", name);
	printf("Option: -h for help\n");
	printf("Option: -a for analysis on startup\n");
	printf("Option: -w to open the file with write permissions\n");
}

void print_banner()
{
	printf(
	" _____                              _   \n"
	"|  __ \\                            | |  \n"
	"| |__) |_____   _____ _ __ ___  ___| |_ \n"
	"|  _  // _ \\ \\ / / _ \\ '__/ __|/ _ \\ __|\n"
	"| | \\ \\  __/\\ V /  __/ |  \\__ \\  __/ |_ \n"
	"|_|  \\_\\___| \\_/ \\___|_|  |___/\\___|\\__|\n"
	"https://github.com/mithreindeir/reverset\n");
}

int main(int argc, char ** argv)
{
	char * file = NULL;
	int write = 0, anal = 0;

	for (int i = 1; i < argc; i++) {
		if (argv[i][0] == '-') {
			int len = strlen(argv[i]);
			for (int j = 1; j < len; j++) {
				switch (argv[i][j]) {
					case 'w':
						write = 1;
						break;
					case 'h':
						print_help(argv[0]);
						break;
					case 'a':
						anal=1;
						break;
				}
			}
		} else if (!file) {
			file = argv[i];
		} else {
			printf("Unwanted parameter: %s\n", argv[i]);
			print_help(argv[0]);
			return 1;
		}
	}
	if (argc==1) {
		print_help(argv[0]);
		return 1;
	}
	char perm[] = "r+";
	if (!write) perm[1] = 0;
	print_banner();
	if (file) {
		reverset * rev = reverset_init();

		reverset_openfile(rev, file, perm);
		if (anal)
			reverset_analyze(rev->shell->buffer, 0, NULL, rev);
		reverset_sh(rev);
		reverset_destroy(rev);
	}
	return 0;
}
