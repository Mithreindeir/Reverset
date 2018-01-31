#ifndef _X86_COMMON_H
#define _X86_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include "../rdis.h"

//X86 and X64 instruction are almost exactly the same, so I'm trying to put common functionality in a shared file

#define BITS_01(b) ((b&0xC0) >> 6)
#define BITS_234(b) (((b&0x38) >> 3))
#define BITS_567(b) (b&0x7)

#define MASK_SIB_SCALE(b) (BITS_01(b))
#define MASK_SIB_INDEX(b) (BITS_234(b))
#define MASK_SIB_BASE(b) (BITS_567(b))

#define MASK_MODRM_MOD(b) (BITS_01(b))
#define MASK_MODRM_REG(b) (BITS_234(b))
#define MASK_MODRM_RM(b) (BITS_567(b))

#define MODRM_DISPONLY(mod, rm) ((mod == 0) && (rm == 5))
#define MODRM_SIB (4)
#define SIB_NO_INDEX (4)
#define SIB_NO_BASE(mod, base) (base == 5 && (mod == 0 || mod == 1 || mod == 2))


#define GROUP_OFFSET 8

enum x86_modrm_modes
{
	MODRM_INDIRECT,
	MODRM_ONEBYTE,
	MODRM_FOURBYTE,
	MODRM_REGISTER,
};

static char x86_instr_prefix_byte[] = {
	0xF3, 0XF2, 0XF0, 0X67, 0X66
};

static char * x86_instr_prefix_str[] = {
	"repz ", "repnz ", "lock ", NULL, NULL 
};

static char x86_segment_register_byte[] = {
	0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65
};

static char * x86_segment_registers[] = {
	"es", "cs", "ss", "ds", "fs", "gs"
};

static char * x86_control_registers[] = {
	"cr0", "invd", "cr2", "cr3", "cr4", "invd", "invd", "invd"
};

static char * x86_test_registers[] = {
	"tr6", "tr7"
};

static char * x86_debug_registers[] = {
	"dr0", "dr1", "dr2", "dr3", "dr4", "dr5", "dr6", "dr7"
};

static char * x86_xmm_registers[] = {
	"xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7"
};

static char * x86_mm_registers[] = {
	"mm0", "mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm7"
};

static char * x64_general_registers[] = {
	"al", "ax", "eax", "rax",
	"cl", "cx", "ecx", "rcx",
	"dl", "dx", "edx", "rdx",
	"bl", "bx", "ebx", "rbx",
	"ah", "sp", "esp", "rsp",
	"ch", "bp", "ebp", "rbp",
	"dh", "si", "esi", "rsi",
	"bh", "di", "edi", "rdi",
	"r8b", "r8w", "r8d", "r8",
	"r9b", "r9w", "r9d", "r9",
	"r10b", "r10w", "r10d", "r10",
	"r11b", "r11w", "r11d", "r11",
	"r12b", "r12w", "r12d", "r12",
	"r13b", "r13w", "r13d", "r13",
	"r14b", "r14w", "r14d", "r14",
	"r15b", "r15w", "r15d", "r15",
};

char * x64_get_register(int r, int size, int rexb);
char * x86_get_register(int r, int size);

typedef struct instr_pair
{
	char * mnemonic;
	r_meta_t type;
} instr_pair;

static const instr_pair instr_pairs[] = {
	{"and", r_tlogic},
	{"or", r_tlogic},
	{"xor", r_tlogic},
	{"not", r_tlogic},
	//
	{"add", r_tarith},
	{"mul", r_tarith},
	{"imul", r_tarith},
	{"div", r_tarith},
	{"idiv", r_tarith},
	{"adc", r_tarith},
	{"sbb", r_tarith},
	{"sub", r_tarith},
	//
	{"jmp", r_tujump},
	//
	{"jo", r_tcjump},
	{"jno", r_tcjump},
	{"jb", r_tcjump},
	{"jnb", r_tcjump},
	{"jz", r_tcjump},
	{"jnz", r_tcjump},
	{"jbe", r_tcjump},
	{"jnbe", r_tcjump},
	{"js", r_tcjump},
	{"jns", r_tcjump},
	{"jp", r_tcjump},
	{"jnp", r_tcjump},
	{"jl", r_tcjump},
	{"jnl", r_tcjump},
	{"jle", r_tcjump},
	{"jnle", r_tcjump},
	//
	{"mov", r_tdata},
	{"push", r_tdata},
	{"pop", r_tdata},
	{"lea", r_tdata},
	{"movs", r_tdata},
	{"movz", r_tdata},
	{"movsx", r_tdata},
	{"movzx", r_tdata},
	//
	{"call", r_tcall},
	//
	{"ret", r_tret},
	{"retn", r_tret}
};

r_meta_t instr_type(char * mnemonic);

#endif