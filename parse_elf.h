#ifndef PARSE_ELF_H
#define PARSE_ELF_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TO_INT(a, b, c, d) ((a << 24) + (b << 16) + (c << 8) + d)
#define TO_LITTLE_ENDIAN(a, b, c, d) (TO_INT(d,c,b,a))

typedef enum ELF_CLASS
{
	ELF_X86 = 1,
	ELF_X64
} ELF_CLASS;

//Type of file
typedef enum ELF_TYPE
{
	ELF_REL = 1,
	ELF_EXEC,
	ELF_DYN,
	ELF_CORE
} ELF_TYPE;

//Target instruction set
typedef enum ELF_INSET
{
	ELF_NOINS,
	ELF_SPARC_SET = 2,
	ELF_X86_SET = 3,
	ELF_MIPS_SET = 8,
	ELF_PPC_SET = 0x14,
	ELF_ARM_SET = 0x28,
	ELF_SUPERH_SET = 0x2a,
	ELF_IA64_SET = 0x3e,
	ELF_ARCH64 = 0xb7
} ELF_INSET;

//OSABI type
typedef enum ELF_OSABI
{
	ELF_SYSV,
	ELF_OSABI_OTHER
} ELF_OSABI; 

//Endiannes
typedef enum ELF_ENDIAN
{
	ELF_LITTLE_ENDIAN,
	ELF_BIG_ENDIAN
} ELF_ENDIAN;

typedef enum SYMBOL_TYPE
{
	STT_NOTYPE,
	STT_OBJECT,
	STT_FUNC,
	STT_SECTION,
	STT_FILE,
	STT_COMMON,
	STT_TLS,
	STT_LOOS,
	STT_HIOS,
	STT_LOPROC,
	STT_REGISTER,
	STT_HIPROC
} SYMBOL_TYPE;

typedef enum BIND_TYPE
{
	LOCAL,
	GLOBAL,
	WEAK,
	LOOS = 10,
	HIOS = 12,
	LOPROC = 13,
	HIPROC = 15
} BIND_TYPE;

typedef enum VISIBILITY
{
	DEFAULT
} VISIBILITY;

typedef struct elf_section
{
	//Entry point of the program
	unsigned int entry_point;
	//Address of the program header table
	unsigned int phead;
	//Address of section header table
	unsigned int shead;
	//Depends on target architecture
	unsigned int flags;
	//Size of header
	unsigned int hsize;
	//Number of entries in program header
	unsigned int phnum;
	//Size of section headers
	unsigned int shsize;
	//Size of program header
	unsigned int phsize;
	//Number of entries in section header
	unsigned int shnum;
	//Index of section names in section header
	unsigned int sec_names;
} elf_section;

typedef struct elf_section_data
{
	char * name;
	char * data;
	unsigned int size;
	unsigned int type;
	unsigned int flags;
	unsigned int offset;
} elf_section_data;

typedef struct elf_symbol
{
	//Index to object files symbol string table that holds name for this symbol
	unsigned int name;
	//Abolute value or address. Holds virtual address if executable or shared object
	unsigned int value;
	//Number of bytes contained by symbol
	unsigned int size;
	//Binding (eg local, global)
	unsigned char binding;
	//Visibility
	unsigned char visibility;
} elf_symbol;

typedef struct elf_file
{
	elf_section_data ** sections;
	int num_sections;

	elf_symbol * symbols;
	int num_symbols; 

	unsigned int entry_point;
} elf_file;

typedef struct elf_section_header
{
	char * sh_name;
	char * sh_type;
	char * sh_flags;
	unsigned int addr;
	unsigned int offset;
	unsigned int size;
	char * link;
	char * info;
	unsigned int addr_align;
	unsigned int entsize;
} elf_section_header;

typedef struct elf_data
{
	ELF_CLASS bits;  	// 32 or 64
	ELF_TYPE type;		//DYN, EXEC, REL, or CORE
	ELF_INSET machine;	//Target instruction set
	ELF_OSABI osabi;	//Target os ABI: Unix-system V, hp-ux, netbsd...
	ELF_ENDIAN endian; 	//big or little

	int version;	//Version 1
	int abiv;	//ABI version
	int version2;	//Duplicate of version

	//Holds index size and number of sections
	elf_section section_info;

} elf_data;

//.ELF
static const char elfmagic[] = {0x7f, 0x45, 0x4c, 0x46};
void little_endian_copy(unsigned int * dst, unsigned char * src);
void read_bytes(FILE * fp, unsigned char * dst, int num_bytes);
void read_int(unsigned int * dst, FILE * fp, ELF_ENDIAN endian);
void read_half_int(unsigned int * dst, FILE * fp);

void read_elf_symbols(elf_file * elf);
void read_elf_sections(elf_file * elf, elf_data * ef, FILE * fp);
void read_elf_data(elf_data * ef, FILE * fp);
elf_file * read_elf(char * filename);



#endif