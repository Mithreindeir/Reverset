#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "colors.h"

void printfhex(unsigned char v)
{
	unsigned char h, l;
	h = (v & 0xf0) >> 4;
	l = v & 0x0f;

	if (h <= 9) h += '0';
	else h = h + 'a' - 10;

	if (l <= 9) l += '0';
	else l = l + 'a' - 10;

	printf("%c%c", h, l);

}

int sizeof_file(FILE* f)
{
	int c = 0;
	while (fgetc(f) != EOF) c++;
	rewind(f);
	return c;
}

int main(int argc, char ** argv)
{
	if (argc < 2) {
		printf("usage: %s filename\n", argv[0]);
		return 1;
	}

	struct winsize win;
	ioctl(STDOUT_FILENO, TIOCGWINSZ, &win);

	FILE * f = fopen(argv[1], "r");
	char c = fgetc(f);
	int eof = 0;
	int cpl = 0;
	int width = 16;
	int file_pos = 0;

	while (1) {
		printf(GRN);
		printf("%08x  ", file_pos);
		printf(RESET);
		printf(CYN);
		while (cpl != width) {
			if (cpl % 2 == 0 && cpl != 0) {
				printf(" ");
			}
		
			if (eof) printfhex(0xff);
			else printfhex(c);
			c = fgetc(f);
			eof = c == EOF;
			cpl++;
			file_pos++;
		}
		printf(RESET);
		cpl = 0;
		printf("  " RED);
		if (eof) break;
		else  {
			fseek(f, file_pos - 16, SEEK_SET);
			int cp = 0;
			c = fgetc(f);
			while (cp != width) {
				if (c >= 0x20 && c  <= 0x7e) {
					printf("%c", c);
				} else {
					printf("." RED);
				}
				c = fgetc(f);
				cp++;
			}
		}

		printf("\n" RESET);

	}
	printf("\n" RESET );
	fclose(f);	
	return 0;
}
