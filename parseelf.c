#include <stdio.h>
#include <stdlib.h>

struct elf_data
{
	int bits;  	// 32 or 64
	int endian; 	//big or little
	int version;	//Version 1
	int osabi;	//Target os ABI: Unix-system V, hp-ux, netbsd...
	int abiv;	//ABI version
	int type;	//DYN, EXEC, REL, or CORE
	int machine;	//Target instruction set
	int version2;	//Duplicate of version
	int entry;	//Entry point of program
	int phead;	//Addr of program header table
	int shead;	//Addr of section header table
	int flag;	//Depends on target architecture
	int hsize;	//Size of header
	int phsize;	//Program header size
	int phnum;	//Number of entries in prog header
	int shnum;	//Number of entries in section header
	int hndx;	//Index of of section names in sec header table 
	
};

char elfmagic[] = {
	0x7f, 0x45, 0x4c, 0x46};

//, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 
//};i

int check_elf(FILE * fp)
{
	char c;
	int i = 0;
	while (i < 4) {
		c = fgetc(fp);
		if (c != elfmagic[i]) {
			return 0;
		}
		i++;
	}
	return 1;
}

int main (int argc, char ** argv)
{
	if (argc < 2) {
		printf("usage: %s file\n", argv[0]);
		return 0;
	}
	FILE * f;
	f = fopen(argv[1], "r");
	
	struct elf_data ef;

	int header = 7;
	while (header >= 0) {
		char c = fgetc(f);
		//printf("%x ", c);
		header--;	
	}
	rewind(f);

	if (check_elf(f)) {
		printf("ELF ");
	} else {
		printf("NOT AN ELF!\n");
		return 1;
	}
	char c = fgetc(f);
	ef.bits = c;
	if (c == 0x01) {
		printf("32 Bit\n");
	} else if (c == 0x02) {
		printf("64 Bit\n");
	}
	c = fgetc(f);
	ef.endian = c;
	if (c == 0x01) {
		printf("Little-endian\n");
	} else if (c == 0x02) {
		printf("Big-endian\n");
	}
	c = fgetc(f);
	ef.version = c;
	if (c == 0x01)
		printf("Version 1\n");

	c = fgetc(f);
	ef.osabi = c;
	if (c == 0x00) {
		printf("Unix System V\n");
	} else {
		printf("Other\n");
	}

	c = fgetc(f);
	ef.abiv = c;
	printf("ABI VERSION: %d\n", c);
	
	c = fgetc(f);
	fclose(f);
	return 0;
}
