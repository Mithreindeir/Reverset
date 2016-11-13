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
	unsigned char c = fgetc(f);
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
	
	//cycle through padding bytes
	for (int i = 0; i < 6;i++) c = fgetc(f);
	
	c = fgetc(f);
	c = fgetc(f);//Two bytes
	ef.type = c;
	switch (c) {
		case 1:
			printf("REL\n");
			break;
		case 2:
			printf("EXEC\n");
			break;
		case 3:
			printf("DYN\n");
			break;
		case 4:
			printf("CORE\n");
			break;
	}
	
	c = fgetc(f);
	c = fgetc(f);	//Two bytes
	ef.machine = c;
	switch (c) {
		case 0:
			printf("No specific instr set\n");
			break;
		case 2:
			printf("SPARC\n");
			break;
		case 3:
			printf("x86\n");
			break;
		case 8:
			printf("MIPS\n");
			break;
		case 0x14:
			printf("PowerPC\n");
			break;
		case 0x28:
			printf("ARM\n");
			break;
		case 0x2a:
			printf("SuperH\n");
			break;
		case 0x32:
			printf("IA-64\n");
			break;
		case 0x3e:
			printf("x86-64\n");
			break;
		case 0xb7:
			printf("AArch64\n");
			break;
	}
	//duplicate of version...
	c = fgetc(f);
	c = fgetc(f);
	c = fgetc(f);
	c = fgetc(f);
	c = fgetc(f);
	//Entry point
	if (ef.bits == 1) {
		unsigned int th, lh, tl, hl;
		if (ef.endian == 0x01) {
			hl = fgetc(f);
			tl = fgetc(f);
			lh = fgetc(f);
			th = fgetc(f);
		} else if (ef.endian == 0x02) {
			th = fgetc(f);
			lh = fgetc(f);
			tl = fgetc(f);
			hl = fgetc(f);
		}
		unsigned int addr = (th << 24) + (lh << 16) + (tl << 8) + hl;
		ef.entry = addr;
		printf("Entry point: %04x\n", addr);

	} else {
		unsigned long addr = 0;
		for (int i = 0; i < 8; i++) {
			c = fgetc(f);
			addr += (c << 8*(8-i+1));
		}
		ef.entry = addr;
		unsigned int a, b;
		a = addr & 0xFFFFFFFF00000000;
		b = addr & 0x00000000FFFFFFFF;
		printf("Entry point: %04x%04x\n", a, b);
	}
	
	//Program header table

	fclose(f);
	return 0;
}
