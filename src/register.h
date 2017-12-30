#ifndef REGISTER_H
#define REGISTER_H

typedef struct x86_reg {
	char map;
	union {
		struct {
			char * reg8;
			char * reg16;
			char * reg32;
		};
		char * regs[3];
	};
} x86_reg;

static const x86_reg x86_registers[8] = {
	{0x00, "al", "ax", "eax" },
	{0x01, "cl", "cx", "ecx" },
	{0x02, "dl", "dx", "edx" },
	{0x03, "bl", "bx", "ebx" },
	{0x04, "ah", "sp", "esp" },
	{0x05, "ch", "bp", "ebp" },
	{0x06, "sh", "si", "esi" },
	{0x07, "bh", "di", "edi" }
};

//Segment registers
enum segment_regs
{
	CS,
	SS,
	DS,
	ES,
	FS,
	GS 
};

typedef struct x86_sreg {
	char map;
	char * reg;
} x86_sreg;

static const x86_sreg x86_segment_registers[6] = {
	{0x2E, "cs"},
	{0x36, "ss"},
	{0x3E, "ds"},
	{0x26, "es"},
	{0x64, "fs"},
	{0x65, "gs"},
};

#endif