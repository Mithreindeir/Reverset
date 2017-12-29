#include "parse_elf.h"

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

void little_endian_copy(u_int32_t * dst, unsigned char * src)
{
	char buf[sizeof(u_int32_t)];
	for (int i = 0; i < sizeof(u_int32_t); i++) {
		buf[sizeof(u_int32_t)-i] = src[i];
	}
	*dst = *((u_int32_t*)buf);
}

void read_bytes(FILE * fp, unsigned char * dst, int num_bytes)
{
	if (!dst) {
		for (int i = 0; i < num_bytes; i++) fgetc(fp);
		return;
	}
	for (int i = 0; i < num_bytes; i++) {
		dst[i] = fgetc(fp);
	}
}

void read_int(u_int32_t * dst, FILE * fp, ELF_ENDIAN endian)
{
	char buf[4];
	read_bytes(fp, buf, 4);
	
	if (endian == ELF_LITTLE_ENDIAN) {
		little_endian_copy(dst, buf);
	} else if (endian == ELF_BIG_ENDIAN) {
		*dst = *((u_int32_t *)buf);
	}
}

void read_half_int(u_int32_t * dst, FILE * fp)
{
	u_int32_t a, b;
	a = fgetc(fp);
	b = fgetc(fp);
	u_int32_t hint = (b << 8) + a;
	*dst = hint;
}

void read_elf_data(elf_data * ef, FILE * fp)
{
	unsigned char c = fgetc(fp);
	ef->bits = c;
	c = fgetc(fp);
	ef->endian = c;
	c = fgetc(fp);
	ef->version = c;

	c = fgetc(fp);
	ef->osabi = c;
	c = fgetc(fp);
	ef->abiv = c;	
	//cycle through padding bytes
	read_bytes(fp, NULL, 8);
	ef->type = c;
	read_bytes(fp, NULL, 2);
	ef->machine = c;
	//duplicate of version...
	read_bytes(fp, NULL, 5);
}

void x86_read_elf_sections(elf_file * elf, elf_data * ef, FILE * fp)
{
	if (ef->bits != ELF_X86) {
		printf("File not x86\n");
		return;
	}

	//read_int copies bytes with specified endianness
	read_int(&ef->section_info.entry_point, fp, ef->endian);
	read_int(&ef->section_info.phead, fp, ef->endian);
	read_int(&ef->section_info.shead, fp, ef->endian);
	read_int(&ef->section_info.flags, fp, ef->endian);

	//read_half_int takes 2 bytes and shifts the first by eight and adds them
	read_half_int(&ef->section_info.hsize, fp);
	read_half_int(&ef->section_info.phsize, fp);
	read_half_int(&ef->section_info.phnum, fp);
	read_half_int(&ef->section_info.shsize, fp);
	read_half_int(&ef->section_info.shnum, fp);
	read_half_int(&ef->section_info.sec_names, fp);
/*
	printf("Entry point %08x\n", ef->section_info.entry_point);
	printf("Program header %08x\n", ef->section_info.phead);
	printf("Section header %08x\n", ef->section_info.shead);
	printf("Flags %08x\n", ef->section_info.flags);

	printf("Header Size: %d\n", ef->section_info.hsize);
	printf("Program Header Size: %d\n", ef->section_info.shsize);
	printf("Entries in Program Header: %d\n", ef->section_info.phnum);
	printf("Section Header size: %d (bytes)\n", ef->section_info.shsize);
	printf("Entries in Section Header: %d\n", ef->section_info.shnum);
	printf("Section names index: %d\n", ef->section_info.sec_names);
*/
	fseek(fp, ef->section_info.shead + ef->section_info.sec_names*ef->section_info.shsize, SEEK_SET);
	elf_section_header elf_hdr;
	int s = sizeof(elf_section_header);
	fread(&elf_hdr, s, 1, fp);
	u_int32_t names_addr = elf_hdr.offset;
	//printf("names_addr %x\n", names_addr);

	elf->sections = malloc(sizeof(elf_section_data*) * ef->section_info.shnum);
	elf->num_sections = ef->section_info.shnum;
	//7D42 is start of first name
	for (int i = 0; i < ef->section_info.shnum; i++) {
	
		//7DE3
		fseek(fp, ef->section_info.shead + i*ef->section_info.shsize, SEEK_SET);
		//elf_hdr;
		int s = sizeof(elf_section_header);
		fread(&elf_hdr, s, 1, fp);
		//printf("%x %x %x %x\n", elf_hdr.sh_name, elf_hdr.sh_type, elf_hdr.addr, elf_hdr.offset);
		char * name = NULL;
		u_int32_t t=0;
		fseek(fp, elf_hdr.sh_name+names_addr, SEEK_SET);
		//read_int(&t, fp, ef->endian);	
		//printf("[%d] ", i);
		//printf("Name: ");
		char buf[256];
		memset(buf, 256, 0);
		int size = 0;
		
		char c = fgetc(fp);
		while (c && (i < 255)) {
			//printf("%c", c);
			buf[size] = c;
			c = fgetc(fp);
			size++;
		}
		buf[size] = 0;
		elf_section_data * section = malloc(sizeof(elf_section_data));
		section->size = elf_hdr.size;
		section->offset = elf_hdr.offset;
		section->flags = elf_hdr.sh_flags;

		section->data = malloc(section->size);
		section->name = strdup(buf);

		fseek(fp, section->offset, SEEK_SET);
		fread(section->data, section->size, 1, fp);
		elf->sections[i] = section;

		//printf(" Type: %d", elf_hdr.sh_type);
		//printf(" Addr: %08x", elf_hdr.addr);
		//printf(" Offs: %08x", elf_hdr.offset);
		//printf(" Size: %08x", elf_hdr.size);
		//printf("%p\n", elf_hdr.sh_name+names_addr);
		//printf("\n");
	}
	read_elf_symbols(elf);
}

void read_elf_symbols(elf_file * elf)
{
	if (!elf) return;

	int symt = -1;
	for (int i = 0; i < elf->num_sections; i++) {
		if (!strcmp(".symtab", elf->sections[i]->name)) {
			symt = i;
			break;
		}
	}
	if (symt == -1) return;
	elf_section_data * symtab = elf->sections[symt];
	printf("Printing %s %d %d:\n", symtab->name, symtab->size, sizeof(elf_symbol));
	for (int i = 0; i < symtab->size; i++) {
		printf("%02x ", symtab->data[i]);
	}

}

elf_file * read_elf (char * file)
{
	FILE * f;
	f = fopen(file, "r");
	if (!f) {
		printf("Error opening file %s\n", file);
		return NULL;
	}
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
		return NULL;
	}
	elf_data * ef = malloc(sizeof(elf_data));
	read_elf_data(ef, f);
	if (ef->bits != ELF_X86) {
		printf("Only x86 supported\n");
		free(ef);
		return NULL;
	}
	elf_file * elf = malloc(sizeof(elf_file));
	elf->sections = NULL;
	elf->num_sections = 0;

	x86_read_elf_sections(elf, ef, f);
	elf->entry_point = ef->section_info.entry_point;
	//Program header
	rewind(f);
	fclose(f);
	free(ef);

	return elf;
}
