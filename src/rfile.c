#include "rfile.h"

r_file * r_file_init()
{
	r_file * file = malloc(sizeof(r_file));
	
	file->symbols = NULL;
	file->num_symbols = 0;

	file->sections = NULL;
	file->num_sections = 0;

	file->raw_file = NULL;
	file->size = 0;
	file->entry_point = 0;
	file->arch = r_noarch;

	file->strings = NULL;
	file->num_strings = 0;

	file->file = NULL;

	return file;
}

void r_file_find_strings(r_file * file)
{
	//Finds all printable strings that are at least 3 valid chars long with an unprintable character after.
	//Only look in PROGBITS section
	for (int i = 0; i < file->num_sections; i++) {
		if (file->sections[i].type == r_programdefined && !!strcmp(file->sections[i].name, ".text")) {
			//Program defined usually contains text and data sections 
			int print_start = -1;
			for (int j = 0; j < file->sections[i].size; j++) {
				char c = file->sections[i].raw[j];
				if (c >= 0x20 && c < 0x127) {
					if (print_start == -1) print_start = j;
				} else {
					if (print_start != -1 && (j-print_start) >= 2) {
						char buf[256];
						memset(buf, 0, 256);
						for (int k = print_start; k < j && ((k-print_start) < 255); k++) {
							buf[k-print_start] = file->sections[i].raw[k];
						}
						rstring str;
						str.string = strdup(buf);
						str.addr64 = file->sections[i].start + print_start;
						str.len = strlen(buf);
						file->num_strings++;
						if (file->num_strings == 1) {
							file->strings = malloc(sizeof(rstring));
						} else {
							file->strings = realloc(file->strings, sizeof(rstring) * file->num_strings);
						}
						file->strings[file->num_strings-1] = str;
					}
					print_start = -1;
				}
			}	
		}
	}
}

rstring * r_file_in_string(r_file * file, uint64_t addr)
{
	for (int i = 0; i < file->num_strings; i++) {
		int d = addr - file->strings[i].addr64;
		if (d >= 0 && d <= file->strings[i].len) return &file->strings[i];
	}
	return NULL;
}

void r_file_patch(r_file * file, uint64_t addr, unsigned char * bytes, int num_bytes)
{
	if (!file->file) return;
	rsection * section = r_file_section_addr(file, addr);
	if (!section) return;


	uint64_t diff = addr - section->start;
	fseek(file->file, section->offset + diff, SEEK_SET);
	int written = fwrite(bytes, 1, num_bytes, file->file);
	uint64_t off = section->offset + diff;
	for (int i = off; i < (off+written); i++) {
		file->raw_file[i] = bytes[i-off];
		section->raw[i-section->offset] = bytes[i-off];
	}

	printf("%d bytes written\n", written);
}

void r_file_destroy(r_file * file)
{
	if (!file) return;

	if (file->file) fclose(file->file);
	//Free symbols
	for (int i = 0; i < file->num_symbols; i++) {
		free(file->symbols[i].name);
	}
	if (file->symbols) free(file->symbols);
	//Free sections
	for (int i = 0; i < file->num_sections; i++) {
		free(file->sections[i].name);
		free(file->sections[i].raw);
	}
	for (int i = 0; i < file->num_strings; i++) {
		free(file->strings[i].string);
	}
	if (file->strings) free(file->strings);

	if (file->sections) free(file->sections);
	if (file->raw_file) free(file->raw_file);

	free(file);
}

rsection * r_file_get_section(r_file * file, char * name)
{
	for (int i = 0; i < file->num_sections; i++) {
		if (!file->sections[i].name || !file->sections[i].name[0]) continue;
		if (!strcmp(name, file->sections[i].name)) {
			return &file->sections[i];
		}
	}
	return NULL;
}

rsection * r_file_section_addr(r_file * file, uint64_t addr)
{
	for (int i = 0; i < file->num_sections; i++) {
		if (addr >= file->sections[i].start && addr < (file->sections[i].start + file->sections[i].size)) return &file->sections[i];
	}
	return NULL;
}