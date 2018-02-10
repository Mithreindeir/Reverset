#include "read_elf.h"

void elf_read_file(FILE * f, r_file * file)
{
	file->bits = fgetc(f);
	rewind(f);
	if (file->bits == ELFCLASS32) {
		elf_read32(f, file);
	} else if (file->bits == ELFCLASS64) {
		elf_read64(f, file);
	}
	//Copy the entire file into r_file
	fseek(f, 0, SEEK_END);
	int len = ftell(f);
	rewind(f);
	file->raw_file = malloc(len);
	file->size = len;
	fread(file->raw_file, len, 1, f);
}

void elf_read32(FILE * f, r_file * file)
{
	Elf32_Ehdr header;
	fread(&header, ALIGNED_SIZEOF(Elf32_Ehdr), 1, f);
	//Set r_files architecture, entry_point and number of sections
	switch (header.e_machine) {
		case EM_ARM:
			file->arch = r_arm;
			break;
		case EM_X86_64:
			file->arch = r_x86_64;
			break;
		case EM_386:
			file->arch = r_x86;
			break;
		default:
			printf("Architecture unsupported\n");
			return;
			break;
	}
	//Set the ABI
	switch (header.e_ident[8]) {
		case ELFOSABI_NONE://abi_none = sysv
			file->abi = rc_sysv32;
			break;
		default:
			file->abi = rc_other;
	}
	file->entry_point = header.e_entry;
	/*Find segments */
	fseek(f, header.e_phoff, SEEK_SET);
	Elf32_Phdr * segments = malloc(sizeof(Elf32_Phdr) * header.e_phnum);
	fread(segments, sizeof(Elf32_Phdr) * header.e_phnum, 1, f);

	file->num_sections = header.e_shnum;

	file->sections = malloc(sizeof(rsection) * file->num_sections);
	memset(file->sections, 0, sizeof(rsection) * file->num_sections);
	//Seek to section header offset to read the section entries
	fseek(f, header.e_shoff, SEEK_SET);

	Elf32_Shdr *sections = malloc(sizeof(Elf32_Shdr) * header.e_shnum);
	fread(sections, sizeof(Elf32_Shdr)*header.e_shnum, 1, f);
	int names_offset = -1;
	//If there is a section name string table then go to it
	if (header.e_shstrndx != SHN_UNDEF) {
		names_offset = sections[header.e_shstrndx].sh_offset;
	}
	for (int i = 0; i < header.e_shnum; i++) {
		rsection r;
		memset(&r, 0, sizeof(rsection));
		r.name = NULL;
		r.offset = sections[i].sh_offset;
		r.size = sections[i].sh_size;
		r.start = sections[i].sh_addr;
		r.type = r_notype;
		r.perm = 0;
		if (sections[i].sh_type == SHT_PROGBITS) {
			r.type = r_programdefined;
		} else if (sections[i].sh_type == SHT_SYMTAB) {
			r.type = r_symboltab;
		} else if (sections[i].sh_type == SHT_STRTAB) {
			r.type = r_stringtab;
		} else if (sections[i].sh_type != SHT_NULL) {
			r.type = r_other;
		}
		//Copy the raw bytes into the rsection
		fseek(f, sections[i].sh_offset, SEEK_SET);
		r.raw = malloc(r.size+1);
		memset(r.raw, 0, r.size+1);
		fread(r.raw, r.size, 1, f);
		//If there is a section name table read the name
		if (names_offset != -1) {
			fseek(f, names_offset+sections[i].sh_name, SEEK_SET);
			char c = fgetc(f);
			int iter = 0;
			char buf[256];
			while (c && iter < 256) {
				buf[iter++] = c;
				c = fgetc(f);
			}
			buf[iter] = 0;
			r.name = strdup(buf);
		}
		/*Find the segment its in and set permissions*/
		for (int j = 0; j < header.e_phnum; j++) {
			if (segments[j].p_vaddr <= r.start && (segments[j].p_vaddr + segments[j].p_memsz) >= (r.size + r.start)) {
				r.perm = segments[j].p_flags;
				break;
			}
		}
		file->sections[i] = r;
	}
	free(segments);
	int strtabidx = -1;
	//Find STRTAB
	for (int i = 0; i < header.e_shnum; i++) {
		if (!strcmp(file->sections[i].name, ".strtab")) {
			strtabidx = i;
			break;
		}
	}

	rsection r;
	if (strtabidx != -1) r = file->sections[strtabidx];
	file->num_symbols = 0;
	//Look for sections of type SHT_SYMTAB and find symbols
	for (int i = 0; i < file->num_sections; i++) {

		if (sections[i].sh_type == SHT_SYMTAB) {
			int num_symbols = sections[i].sh_size/sizeof(Elf32_Sym);
			Elf32_Sym * symbols = (Elf32_Sym*)(file->sections[i].raw);
			for (int j = 0; j < num_symbols; j++) {
				if (strtabidx != -1) {
					int iter = 0;
					char c = r.raw[symbols[j].st_name];
					char buf[256];
					while (c && iter < 256) {
						buf[iter++] = c;
						c = r.raw[symbols[j].st_name + iter];
					}
					buf[iter] = 0;
					//Do not use unknown or no type symbols
					if (buf[0] != 0 && (elft_to_rsymt(ELF32_ST_TYPE(symbols[j].st_info)) != R_NONE)) {
						//Only make rsymbol if the string is not NULL
						rsymbol rsym;
						rsym.name = strdup(buf);
						rsym.type = elft_to_rsymt(ELF32_ST_TYPE(symbols[j].st_info));
						//rsym.type = symbols[j].st_type;
						rsym.addr64 = symbols[j].st_value;

						file->num_symbols++;
						if (file->num_symbols == 1) {
							file->symbols = malloc(sizeof(rsymbol));
						} else {
							file->symbols = realloc(file->symbols, sizeof(rsymbol) * file->num_symbols);
						}
						file->symbols[file->num_symbols-1] = rsym;
					}
				}

			}

		}
	}
	//Find Reloc section a create symbols using address of the jmp instruction
	//Find DYNSTR
	for (int i = 0; i < header.e_shnum; i++) {
		if (!strcmp(file->sections[i].name, ".dynstr")) {
			strtabidx = i;
			break;
		}
	}

	if (strtabidx != -1) r = file->sections[strtabidx];
	rsymbol * dynsymbols = NULL;
	int num_dynsyms = 0;

	//Look for sections of type SHT_DYNSYM and find symbols
	for (int i = 0; i < header.e_shnum; i++) {
		if (sections[i].sh_type == SHT_DYNSYM) {
			int num_symbols = sections[i].sh_size/sizeof(Elf32_Sym);
			Elf32_Sym * symbols = (Elf32_Sym*)(file->sections[i].raw);
			for (int j = 0; j < num_symbols; j++) {
				if (strtabidx != -1) {
					int iter = 0;
					char c = r.raw[symbols[j].st_name];
					char buf[256];
					while (c && iter < 256) {
						buf[iter++] = c;
						c = r.raw[symbols[j].st_name + iter];
					}
					buf[iter] = 0;
					//Do not use unknown or no type symbols
					rsymbol rsym;
					rsym.name = strdup(buf);
					rsym.type = elft_to_rsymt(ELF32_ST_TYPE(symbols[j].st_info));
					//rsym.type = symbols[j].st_type;
					rsym.addr64 = symbols[j].st_value;
					num_dynsyms++;
					if (num_dynsyms == 1) {
						dynsymbols = malloc(sizeof(rsymbol));
					} else {
						dynsymbols = realloc(dynsymbols, sizeof(rsymbol) * num_dynsyms);
					}
					dynsymbols[num_dynsyms-1] = rsym;
				}

			}

		}
	}

	//Look for sections of type SHT_RELA and find reloc symbols
	for (int i = 0; i < header.e_shnum; i++) {

		if (sections[i].sh_type == SHT_REL) {
			int num_symbols = sections[i].sh_size/sizeof(Elf32_Rel);
			Elf32_Rel * symbols = (Elf32_Rel*)(file->sections[i].raw);
			for (int j = 0; j < num_symbols; j++) {
				//Only make rsymbol if the string is not NULL
				int si = ELF32_R_SYM(symbols[j].r_info);
				if (si > num_dynsyms) continue;
				rsymbol rsym;
				rsym.name = dynsymbols[si].name;
				dynsymbols[si].name = NULL;
				rsym.type = elft_to_rsymt(ELF32_R_TYPE(symbols[j].r_info)) | R_RELOCBIT;
				//rsym.type = symbols[j].st_type;
				rsym.addr64 = symbols[j].r_offset;
				file->num_symbols++;
				if (file->num_symbols == 1) {
					file->symbols = malloc(sizeof(rsymbol));
				} else {
					file->symbols = realloc(file->symbols, sizeof(rsymbol) * file->num_symbols);
				}
				file->symbols[file->num_symbols-1] = rsym;			
			}
		} else if (sections[i].sh_type == SHT_RELA) {
			int num_symbols = sections[i].sh_size/sizeof(Elf32_Rela);
			Elf32_Rela * symbols = (Elf32_Rela*)(file->sections[i].raw);
			for (int j = 0; j < num_symbols; j++) {
				//Only make rsymbol if the string is not NULL
				int si = ELF32_R_SYM(symbols[j].r_info)-1;
				if (si > num_dynsyms) continue;
				rsymbol rsym;
				rsym.name = dynsymbols[si].name;
				dynsymbols[si].name = NULL;
				rsym.type = elft_to_rsymt(ELF32_R_TYPE(symbols[j].r_info)) | R_RELOCBIT;
				//rsym.type = symbols[j].st_type;
				rsym.addr64 = symbols[j].r_offset;
				file->num_symbols++;
				if (file->num_symbols == 1) {
					file->symbols = malloc(sizeof(rsymbol));
				} else {
					file->symbols = realloc(file->symbols, sizeof(rsymbol) * file->num_symbols);
				}
				file->symbols[file->num_symbols-1] = rsym;			
			}
		}
	}
	for (int i = 0; i < num_dynsyms; i++) {
		if (dynsymbols[i].name) free(dynsymbols[i].name);
	}
	if (dynsymbols) free(dynsymbols);
	free(sections);
}

void elf_read64(FILE * f, r_file * file)
{
	Elf64_Ehdr header;
	fread(&header, ALIGNED_SIZEOF(Elf64_Ehdr), 1, f);
	//Set r_files architecture, entry_point and number of sections
	switch (header.e_machine) {
		case EM_ARM:
			file->arch = r_arm;
			break;
		case EM_X86_64:
			file->arch = r_x86_64;
			break;
		case EM_386:
			file->arch = r_x86;
			break;
		default:
			printf("Architecture unsupported\n");
			return;
			break;
	}
	//Set the ABI
	switch (header.e_ident[8]) {
		case ELFOSABI_NONE://abi_none = sysv
			file->abi = rc_sysv64;
			break;
		default:
			file->abi = rc_other;
	}
	file->entry_point = header.e_entry;
	/*Find segments */
	fseek(f, header.e_phoff, SEEK_SET);
	Elf64_Phdr * segments = malloc(sizeof(Elf64_Phdr) * header.e_phnum);
	fread(segments, sizeof(Elf64_Phdr) * header.e_phnum, 1, f);

	file->num_sections = header.e_shnum;
	file->sections = malloc(sizeof(rsection) * file->num_sections);
	memset(file->sections, 0, sizeof(rsection) * file->num_sections);
	//Seek to section header offset to read the section entries
	fseek(f, header.e_shoff, SEEK_SET);

	Elf64_Shdr *sections = malloc(sizeof(Elf64_Shdr) * header.e_shnum);
	fread(sections, sizeof(Elf64_Shdr)*header.e_shnum, 1, f);
	int names_offset = -1;
	//If there is a section name string table then go to it
	if (header.e_shstrndx != SHN_UNDEF) {
		names_offset = sections[header.e_shstrndx].sh_offset;
	}
	for (int i = 0; i < header.e_shnum; i++) {
		rsection r;
		r.name = NULL;
		r.size = sections[i].sh_size;
		r.offset = sections[i].sh_offset;
		r.start = sections[i].sh_addr;
		r.type = r_notype;
		r.perm = 0;
		if (sections[i].sh_type == SHT_PROGBITS) {
			
			r.type = r_programdefined;
		} else if (sections[i].sh_type == SHT_SYMTAB) {
			r.type = r_symboltab;
		} else if (sections[i].sh_type == SHT_STRTAB) {
			r.type = r_stringtab;
		} else if (sections[i].sh_type != SHT_NULL) {
			r.type = r_other;
		}
		//Copy the raw bytes into the rsection
		fseek(f, sections[i].sh_offset, SEEK_SET);
		r.raw = malloc(r.size+1);
		memset(r.raw, 0, r.size+1);
		fread(r.raw, r.size, 1, f);
		//If there is a section name table read the name
		if (names_offset != -1) {
			fseek(f, names_offset+sections[i].sh_name, SEEK_SET);
			char c = fgetc(f);
			int iter = 0;
			char buf[256];
			while (c && iter < 256) {
				buf[iter++] = c;
				c = fgetc(f);
			}
			buf[iter] = 0;
			r.name = strdup(buf);
		}
		/*Find the segment its in and set permissions*/
		for (int j = 0; j < header.e_phnum; j++) {
			if (segments[j].p_vaddr <= r.start && (segments[j].p_vaddr + segments[j].p_memsz) >= (r.size + r.start)) {
				r.perm = segments[j].p_flags;
				break;
			}
		}

		file->sections[i] = r;
	}
	free(segments);
	int strtabidx = -1;
	//Find STRTAB
	for (int i = 0; i < header.e_shnum; i++) {
		if (!strcmp(file->sections[i].name, ".strtab")) {
			strtabidx = i;
			break;
		}
	}
	rsection r;
	if (strtabidx != -1) r = file->sections[strtabidx];
	file->num_symbols = 0;
	//Look for sections of type SHT_SYMTAB and find symbols
	for (int i = 0; i < header.e_shnum; i++) {
		if (sections[i].sh_type == SHT_SYMTAB) {
			int num_symbols = sections[i].sh_size/sizeof(Elf64_Sym);
			Elf64_Sym * symbols = (Elf64_Sym*)(file->sections[i].raw);
			for (int j = 0; j < num_symbols; j++) {
				if (strtabidx != -1) {
					int iter = 0;
					char c = r.raw[symbols[j].st_name];
					char buf[256];
					while (c && iter < 256) {
						buf[iter++] = c;
						c = r.raw[symbols[j].st_name + iter];
					}
					buf[iter] = 0;
					//Do not use unknown or no type symbols
					if (buf[0] != 0 && (elft_to_rsymt(ELF64_ST_TYPE(symbols[j].st_info)) != R_NONE)) {
						//Only make rsymbol if the string is not NULL
						rsymbol rsym;
						rsym.name = strdup(buf);
						rsym.type = elft_to_rsymt(ELF64_ST_TYPE(symbols[j].st_info));
						//rsym.type = symbols[j].st_type;
						rsym.addr64 = symbols[j].st_value;

						file->num_symbols++;
						if (file->num_symbols == 1) {
							file->symbols = malloc(sizeof(rsymbol));
						} else {
							file->symbols = realloc(file->symbols, sizeof(rsymbol) * file->num_symbols);
						}
						file->symbols[file->num_symbols-1] = rsym;
					}
				}

			}

		}
	}
	
	//Find DYNSTR
	for (int i = 0; i < header.e_shnum; i++) {
		if (!strcmp(file->sections[i].name, ".dynstr")) {
			strtabidx = i;
			break;
		}
	}

	if (strtabidx != -1) r = file->sections[strtabidx];
	rsymbol * dynsymbols = NULL;
	int num_dynsyms = 0;

	//Look for sections of type SHT_DYNSYM and find symbols
	for (int i = 0; i < header.e_shnum; i++) {
		if (sections[i].sh_type == SHT_DYNSYM) {
			int num_symbols = sections[i].sh_size/sizeof(Elf64_Sym);
			Elf64_Sym * symbols = (Elf64_Sym*)(file->sections[i].raw);
			for (int j = 0; j < num_symbols; j++) {
				if (strtabidx != -1) {
					int iter = 0;
					char c = r.raw[symbols[j].st_name];
					char buf[256];
					while (c && iter < 256) {
						buf[iter++] = c;
						c = r.raw[symbols[j].st_name + iter];
					}
					buf[iter] = 0;
					//Do not use unknown or no type symbols
					//Only make rsymbol if the string is not NULL
					rsymbol rsym;
					rsym.name = strdup(buf);
					rsym.type = elft_to_rsymt(ELF64_ST_TYPE(symbols[j].st_info));
					//rsym.type = symbols[j].st_type;
					rsym.addr64 = symbols[j].st_value;
					num_dynsyms++;
					if (num_dynsyms == 1) {
						dynsymbols = malloc(sizeof(rsymbol));
					} else {
						dynsymbols = realloc(dynsymbols, sizeof(rsymbol) * num_dynsyms);
					}
					dynsymbols[num_dynsyms-1] = rsym;
				}

			}

		}
	}

	//Look for sections of type SHT_RELA and find reloc symbols
	for (int i = 0; i < header.e_shnum; i++) {
		if (sections[i].sh_type == SHT_REL) {
			int num_symbols = sections[i].sh_size/sizeof(Elf64_Rel);
			Elf64_Rel * symbols = (Elf64_Rel*)(file->sections[i].raw);

			for (int j = 0; j < num_symbols; j++) {
				//Only make rsymbol if the string is not NULL
				int si = ELF64_R_SYM(symbols[j].r_info);
				if (si >= num_dynsyms) continue;
				rsymbol rsym;
				rsym.name = dynsymbols[si].name;
				dynsymbols[si].name = NULL;
				rsym.type = elft_to_rsymt(ELF64_R_TYPE(symbols[j].r_info)) | R_RELOCBIT;
				//rsym.type = symbols[j].st_type;
				rsym.addr64 = symbols[j].r_offset;
				file->num_symbols++;
				if (file->num_symbols == 1) {
					file->symbols = malloc(sizeof(rsymbol));
				} else {
					file->symbols = realloc(file->symbols, sizeof(rsymbol) * file->num_symbols);
				}
				file->symbols[file->num_symbols-1] = rsym;			
			}
		} else if (sections[i].sh_type == SHT_RELA) {
			int num_symbols = sections[i].sh_size/sizeof(Elf64_Rela);
			Elf64_Rela * symbols = (Elf64_Rela*)(file->sections[i].raw);
			for (int j = 0; j < num_symbols; j++) {
				//Only make rsymbol if the string is not NULL
				int si = ELF64_R_SYM(symbols[j].r_info);
				if (si >= num_dynsyms) continue;
				rsymbol rsym;
				rsym.name = dynsymbols[si].name;
				dynsymbols[si].name = NULL;
				rsym.type = elft_to_rsymt(ELF64_R_TYPE(symbols[j].r_info)) | R_RELOCBIT;
				//rsym.type = symbols[j].st_type;
				rsym.addr64 = symbols[j].r_offset;
				file->num_symbols++;
				if (file->num_symbols == 1) {
					file->symbols = malloc(sizeof(rsymbol));
				} else {
					file->symbols = realloc(file->symbols, sizeof(rsymbol) * file->num_symbols);
				}
				file->symbols[file->num_symbols-1] = rsym;			
			}
		}

	}
	for (int i = 0; i < num_dynsyms; i++) {
		if (dynsymbols[i].name) free(dynsymbols[i].name);
	}
	if (dynsymbols) free(dynsymbols);

	free(sections);
}

int elft_to_rsymt(int elfsymt)
{
	switch (elfsymt) {
		case STT_NOTYPE:
			break;
		case STT_OBJECT:
			return R_OBJECT;
			break;
		case STT_FUNC:
			return R_FUNC;
			break;
		default:
			return R_NONE;
			break;
	}
	return R_NONE;
}

int check_elf(FILE * f)
{
	uint32_t elfm;
	fread(&elfm, 4, 1, f);
	return elfm == *((uint32_t*)elf_magic);
}