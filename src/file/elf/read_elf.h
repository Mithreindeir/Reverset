#ifndef _ELF_H
#define _ELF_H

#include <linux/elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../rfile.h"

#define ALIGNED_SIZEOF(x) ((sizeof(x) % 4) + sizeof(x))

static const char elf_magic[] = ELFMAG;

void read_bytes(unsigned char * dst, FILE * f, int endianess, int size);
int check_elf(FILE * fp);
void elf_read_file(FILE * f, rfile * file);
void elf_read32(FILE * f, rfile * file);
void elf_read64(FILE * f, rfile * file);
int elft_to_rsymt(int elfsymt);

#endif