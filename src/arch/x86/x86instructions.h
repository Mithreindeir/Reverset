#ifndef _X86_INSTRUCTIONS_H
#define _X86_INSTRUCTIONS_H

typedef struct x86_instruction {
	char * mnemonic;
	union {
		struct {
			char * op1;
			char * op2;
			char * op3;
		};
		char * op[3];
	};
} x86_instruction;

enum x86_Addressing_Mode {
	X86_INVALID_MODE,
	X86_DIRECT_ADDRESSING = 'A',//Direct addressing. Address of operand is encoded in instruction.
	X86_FPU_REGISTER = 'B',	//The Reg field of Modrm selects a x87 fpu stack register
	X86_FPU_MODRM	= 'H',	//The modrm byte specifies either a x87 fpu stack register or memory address
	X86_CONTROL_REG = 'C',	//Reg field of modrm selects control register
	X86_DEBUG_REG = 'D',	//Reg field of modrm selects debug register
	X86_MODRM = 'E',		//Modrm byte
	X86_FLAGS_REG = 'F',	//Flags register
	X86_REG = 'G',			//Register field holds register
	X86_IMM = 'I',			//Immediate data
	X86_REL = 'J',			//Relative offset
	X86_MEM = 'M',			//Modrm forced to refer to memory
	X86_MOFFSET = 'O',		//No modrm byte. Offset is coded in the instruction
	X86_MOD_REG = 'R',		//Mod firled of modrm refers to general register
	X86_SEG_REG = 'S',		//The register field of the modrm byte codes for a seg reg
	X86_TEST_REG = 'T',		//Reg field of modrm byte codes for a test register
	X86_DSSI_MEM = 'X',		//Memory addressed by DS:SI
	X86_ESDI_MEM = 'Y'		//Memory addressed by ES:DI
};

enum x86_Operand_Size {
	X86_INVALID_SIZE,
	X86_TWO_WORD = 'a', //Two one word operands or two double word operands depending on operand size attribute
	X86_BYTE	 = 'b', //Byte 
	X86_BWORD	 = 'c', //Byte or word depending on operand size
	X86_DWORD	 = 'd', //Double word 
	X86_PTR		 = 'p', //32 or 48 bit pointer depending on operand size
	X86_PDESC	 = 's',	//6 byte pseudo descriptor
	X86_WDWORD	 = 'v',	//Word or dword depending on operand size
	X86_WORD 	 = 'w'	//Word
};

//Follows above operand encoding, unless the first character is in lowercase then the operand becomes that
static const x86_instruction x86_instruction_table[] = {
	//0
	{"add", "Eb", "Gb", ""},
	{"add", "Ev", "Gv", ""},
	{"add", "Gb", "Eb", ""},
	{"add", "Gv", "Ev", ""},
	{"add", "al", "Ib", ""},
	{"add", "eax", "Iv", ""},
	{"push", "es", "", ""},
	{"pop", "es", "", ""},
	{"or", "Eb", "Gb", ""},
	{"or", "Ev", "Gv", ""},
	{"or", "Gb", "Eb", ""},
	{"or", "Gv", "Ev", ""},
	{"or", "al", "Ib", ""},
	{"or", "eax", "Iv", ""},
	{"push", "cs", "", ""},
	{"",	"", 	"", ""},//2 byte escape
	//1
	{"adc", "Eb", "Gb", ""},
	{"adc", "Ev", "Gv", ""},
	{"adc", "Gb", "Eb", ""},
	{"adc", "Gv", "Ev", ""},
	{"adc", "al", "Ib", ""},
	{"adc", "eax", "Iv", ""},
	{"push", "ss", "", ""},
	{"pop", "ss", "", ""},
	{"sbb", "Eb", "Gb", ""},
	{"sbb", "Ev", "Gv", ""},
	{"sbb", "Gb", "Eb", ""},
	{"sbb", "Gv", "Ev", ""},
	{"sbb", "al", "Ib", ""},
	{"sbb", "eax", "Iv", ""},
	{"push", "ds", "", ""},
	{"pop", "ds", "", ""},
	//2
	{"and", "Eb", "Gb", ""},
	{"and", "Ev", "Gv", ""},
	{"and", "Gb", "Eb", ""},
	{"and", "Gv", "Ev", ""},
	{"and", "al", "Ib", ""},
	{"and", "eax", "Iv", ""},
	{"", "", "", ""},	//Es segment register override
	{"daa", "", "", ""},
	{"sub", "Eb", "Gb", ""},
	{"sub", "Ev", "Gv", ""},
	{"sub", "Gb", "Eb", ""},
	{"sub", "Gv", "Ev", ""},
	{"sub", "al", "Ib", ""},
	{"sub", "eax", "Iv", ""},
	{"", "", "", ""}, //Cs segment register override
	{"das", "", "", ""},
	//3
	{"xor", "Eb", "Gb", ""},
	{"xor", "Ev", "Gv", ""},
	{"xor", "Gb", "Eb", ""},
	{"xor", "Gv", "Ev", ""},
	{"xor", "al", "Ib", ""},
	{"xor", "eax", "Iv", ""},
	{"", "", "", ""}, //SS segment register override
	{"aaa", "", "", ""},
	{"cmp", "Eb", "Gb", ""},
	{"cmp", "Ev", "Gv", ""},
	{"cmp", "Gb", "Eb", ""},
	{"cmp", "Gv", "Ev", ""},
	{"cmp", "al", "Ib", ""},
	{"cmp", "eax", "Iv", ""},
	{"", "", "", ""}, //DS segment register override
	{"aas", "", "", ""},
	//4
	{"inc", "eax", "", ""},
	{"inc", "ecx", "", ""},
	{"inc", "edx", "", ""},
	{"inc", "ebx", "", ""},
	{"inc", "esp", "", ""},
	{"inc", "ebp", "", ""},
	{"inc", "esi", "", ""},
	{"inc", "edi", "", ""},
	{"dec", "eax", "", ""},
	{"dec", "ecx", "", ""},
	{"dec", "edx", "", ""},
	{"dec", "ebx", "", ""},
	{"dec", "esp", "", ""},
	{"dec", "ebp", "", ""},
	{"dec", "esi", "", ""},
	{"dec", "edi", "", ""},
	//5
	{"push", "eax", "", ""},
	{"push", "ecx", "", ""},
	{"push", "edx", "", ""},
	{"push", "ebx", "", ""},
	{"push", "esp", "", ""},
	{"push", "ebp", "", ""},
	{"push", "esi", "", ""},
	{"push", "edi", "", ""},
	{"pop", "eax", "", ""},
	{"pop", "ecx", "", ""},
	{"pop", "edx", "", ""},
	{"pop", "ebx", "", ""},
	{"pop", "esp", "", ""},
	{"pop", "ebp", "", ""},
	{"pop", "esi", "", ""},
	{"pop", "edi", "", ""},
	//6
	{"pusha", "", "", ""},
	{"popa", "", "", ""},
	{"bound", "Gv", "Ma", ""},
	{"arpl", "Ew", "Rw", ""},
	{"", "", "", ""}, //FS Segment register override
	{"", "", "", ""}, //GS Segment register override
	{"", "", "", ""}, //Operand size override
	{"", "", "", ""}, //Address size override
	{"push", "Iv", "", ""},
	{"imul", "Gv", "Ev", "Iv"},
	{"push", "Ib", "", ""},
	{"imul", "Gv", "Ev", "Iv"},
	{"insb", "Yb", "dx", ""},
	{"insw", "Yb", "dx", ""},
	{"outsb", "Dx", "Xb", ""},
	{"outsw", "dx", "Xv", ""},
	//7
	{"jo", "Jb", "", ""},
	{"jno", "Jb", "", ""},
	{"jb", "Jb", "", ""},
	{"jnb", "Jb", "", ""},
	{"jz", "Jb", "", ""},
	{"jnz", "Jb", "", ""},
	{"jbe", "Jb", "", ""},
	{"jnbe", "Jb", "", ""},
	{"js", "Jb", "", ""},
	{"jns", "Jb", "", ""},
	{"jp", "Jb", "", ""},
	{"jnp", "Jb", "", ""},
	{"jl", "Jb", "", ""},
	{"jge", "Jb", "", ""},
	{"jle", "Jb", "", ""},
	{"jg", "Jb", "", ""},
	//8
	{"grp1d", "Eb", "Ib", ""},
	{"grp1d", "Ev", "Iv", ""},
	{"grp1d", "Eb", "Ib", ""},
	{"grp1d", "Ev", "Ib", ""},
	{"test", "Eb", "Gb", ""},
	{"test", "Ev", "Gv", ""},
	{"xchg", "Eb", "Gb", ""},
	{"xchg", "Ev", "Gv", ""},
	{"mov", "Eb", "Gb", ""},
	{"mov", "Ev", "Gv", ""},
	{"mov", "Gb", "Eb", ""},
	{"mov", "Gv", "Ev", ""},
	{"mov", "Ew", "Sw", ""},
	{"lea", "Gv", "M", ""},	//Change to Gv, M
	{"mov", "Sw", "Ew", ""},
	{"pop", "Ev", "", ""},
	//9
	{"nop", "", "", ""},	//Could also be xchg eax, eax
	{"xchg", "ecx", "eax", ""},
	{"xchg", "edx", "eax", ""},
	{"xchg", "ebx", "eax", ""},
	{"xchg", "esp", "eax", ""},
	{"xchg", "ebp", "eax", ""},
	{"xchg", "esi", "eax", ""},
	{"xchg", "edi", "eax", ""},
	{"cbw", "", "", ""},
	{"cwd", "", "", ""},
	{"call", "Ap", "", ""},
	{"wait", "", "", ""},
	{"pushf", "Fv", "", ""},
	{"popf", "Fv", "", ""},
	{"sahf", "", "", ""},
	{"lahf", "", "", ""},
	//A
	{"mov", "al", "Ob", ""},
	{"mov", "eax", "Ov", ""},
	{"mov", "Ob", "al", ""},
	{"mov", "Ov", "eax", ""},
	{"movsb", "Xb", "Yb", ""},
	{"movsw", "Xv", "Yv", ""},
	{"cmpsb", "Xb", "Yb", ""},
	{"cmpsw", "Xv", "Yv", ""},
	{"test", "al", "Ib", ""},
	{"test", "eax", "Iv", ""},
	{"stosb", "Yb", "al", ""},
	{"stosw", "Yv", "eax", ""},
	{"lodsb", "al", "Xb", ""},
	{"lodsw", "eax", "Xv", ""},
	{"scasb", "al", "Xb", ""},
	{"scasw", "eax", "Xv", ""},
	//B
	{"mov", "al", "Ib", ""},
	{"mov", "cl", "Ib", ""},
	{"mov", "dl", "Ib", ""},
	{"mov", "bl", "Ib", ""},
	{"mov", "ah", "Ib", ""},
	{"mov", "ch", "Ib", ""},
	{"mov", "dh", "Ib", ""},
	{"mov", "bh", "Ib", ""},
	{"mov", "eax", "Iv", ""},
	{"mov", "ecx", "Iv", ""},
	{"mov", "edx", "Iv", ""},
	{"mov", "ebx", "Iv", ""},
	{"mov", "esp", "Iv", ""},
	{"mov", "ebp", "Iv", ""},
	{"mov", "esi", "Iv", ""},
	{"mov", "edi", "Iv", ""},
	//C
	{"grp2d", "Eb", "Ib", ""},
	{"grp2d", "Ev", "Ib", ""},
	{"ret", "Iw", "", ""},
	{"ret", "", "", ""},
	{"les", "Gv", "Mp", ""},
	{"lds", "Gv", "Mp", ""},
	{"mov", "Eb", "Ib", ""},
	{"mov", "Ev", "Iv", ""},
	{"enter", "Iw", "Ib", ""},
	{"leave", "", "", ""},
	{"retf", "Iw", "", ""},
	{"retf", "", "", ""},
	{"int", "3", "", ""},
	{"int", "Ib", "", ""},
	{"into", "", "", ""},
	{"iret", "", "", ""},
	//D
	{"grp2d", "Eb", "1", ""},
	{"grp2d", "Ev", "1", ""},
	{"grp2d", "Eb", "cl", ""},
	{"grp2d", "Ev", "cl", ""},
	{"aam", "", "", ""},
	{"aad", "", "", ""},
	{"", "", "", ""}, //Not used
	{"xlat", "", "", ""},
	/*Floating Point Instruction Set*/
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	/*End Of Floating Point Instruction Set*/
	//E
	{"loopne", "Jb", "", ""},
	{"loope", "Jb", "", ""},
	{"loop", "Jb", "", ""},
	{"jcxz", "Jb", "", ""},
	{"in", "al", "Ib", ""},
	{"in", "eaxa", "Ib", ""},
	{"out", "Ib", "al", ""},
	{"out", "Ib", "eax", ""},
	{"call", "Av", "", ""},
	{"jnp", "Jv", "", ""},
	{"jnp", "Ap", "", ""},
	{"jmp", "Jb", "", ""},
	{"in", "al", "dx", ""},
	{"in", "eax", "dx", ""},
	{"out", "dx", "al", ""},
	{"out", "dx", "eax", ""},
	//F
	{"", "", "", ""},	//Lock prefix byte
	{"", "", "", ""},	//Not used
	{"", "", "", ""},	//Repne prefix byte
	{"", "", "", ""},	//Rep prefix byte
	{"hlt", "", "", ""},
	{"cmc", "", "", ""},
	{"grp3a", "", "", ""},
	{"grp3b", "", "", ""},
	{"clc", "", "", ""},
	{"stc", "", "", ""},
	{"cli", "", "", ""},
	{"sti", "", "", ""},
	{"cld", "", "", ""},
	{"std", "", "", ""},
	{"grp4d", "Eb", "", ""},
	{"grp5a", "", "", ""}

};

/*Currently only include standard x86 instruction set (no avx, sse, or fpu instructions) which is why its mostly empty*/
static const x86_instruction x86_instruction_extended_table[] = {
	//0
	{"grp6d", "Ew", "", ""},
	{"grp7a", "", "", ""},
	{"lar", "Gw", "Ew", ""},
	{"lsl", "Gv", "Ew", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"ctls", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	//1
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	//2
	{"mov", "Rd", "Cd", ""},
	{"mov", "Rd", "Dd", ""},
	{"mov", "Cd", "Rd", ""},
	{"mov", "Dd", "Rd", ""},
	{"mov", "Rd", "Td", ""},
	{"", "", "", ""},
	{"mov", "Td", "Rd", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	//3
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	//4
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	//5
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	//6
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	//7
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	//8
	{"jo", "Jv", "", ""},
	{"jno", "Jv", "", ""},
	{"jb", "Jv", "", ""},
	{"jnb", "Jv", "", ""},
	{"jz", "Jv", "", ""},
	{"jnz", "Jv", "", ""},
	{"jbe", "Jv", "", ""},
	{"jnbe", "Jv", "", ""},
	{"js", "Jv", "", ""},
	{"jns", "Jv", "", ""},
	{"jp", "Jv", "", ""},
	{"jnp", "Jv", "", ""},
	{"jl", "Jv", "", ""},
	{"jge", "Jv", "", ""},
	{"jle", "Jv", "", ""},
	{"jg", "Jv", "", ""},
	//9
	{"seto", "Eb", "", ""},
	{"setno", "Eb", "", ""},
	{"setb", "Eb", "", ""},
	{"setnb", "Eb", "", ""},
	{"setz", "Eb", "", ""},
	{"setnz", "Eb", "", ""},
	{"setbe", "Eb", "", ""},
	{"setnbe", "Eb", "", ""},
	{"sets", "Eb", "", ""},
	{"setns", "Eb", "", ""},
	{"setp", "Eb", "", ""},
	{"setnp", "Eb", "", ""},
	{"setl", "Eb", "", ""},
	{"setnl", "Eb", "", ""},
	{"setle", "Eb", "", ""},
	{"setnle", "Eb", "", ""},
	//A
	{"push", "fs", "", ""},
	{"pop", "fs", "", ""},
	{"", "", "", ""},
	{"bt", "Ev", "Gv", ""},
	{"shld", "Ev", "Gv", "Ib"},
	{"shld", "Ev", "Gv", "cl"},
	{"", "", "", ""},
	{"", "", "", ""},
	{"push", "gs", "", ""},
	{"pop", "gs", "", ""},
	{"", "", "", ""},
	{"bts", "Ev", "Gv", ""},
	{"shrd", "Ev", "Gv", "Ib"},
	{"shrd", "Ev", "Gv", "cl"},
	{"", "", "", ""},
	{"imul", "Gv", "Ev", ""},
	//B
	{"", "", "", ""},
	{"", "", "", ""},
	{"lss", "Mp", "", ""},
	{"btr", "Ev", "Gv", ""},
	{"lfs", "Mp", "", ""},
	{"lgs", "Mp", "", ""},
	{"movzx", "Gv", "Eb", ""},
	{"movzx", "Gv", "Ew", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"grp8d", "Ev", "Ib", ""},
	{"btc", "Ev", "Gv", ""},
	{"bsf", "Gv", "Ev", ""},
	{"bsr", "Gv", "Ev", ""},
	{"movsx", "Gv", "Eb", ""},
	{"movsx", "Gv", "Ew", ""},
	//C
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	//D
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	//E
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	//F
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},

};

//Opcode extension groups
static const x86_instruction x86_grp1[] = {
	{"add", "", "", ""},
	{"or", "", "", ""},
	{"adc", "", "", ""},
	{"sbb", "", "", ""},
	{"and", "", "", ""},
	{"sub", "", "", ""},
	{"xor", "", "", ""},
	{"cmp", "", "", ""}
};

static const x86_instruction x86_grp2[] = {
	{"rol", "", "", ""},
	{"ror", "", "", ""},
	{"rcl", "", "", ""},
	{"rcr", "", "", ""},
	{"shl", "", "", ""},
	{"shr", "", "", ""},
	{"sal", "", "", ""},
	{"sar", "", "", ""}
};

static const x86_instruction x86_grp3[] = {
	{"test", "Eb", "Ib", ""},
	{"test", "Eb", "Ib", ""},
	{"not", "Eb", "", ""},
	{"neg", "Eb", "", ""},
	{"mul", "al", "Eb", ""},
	{"imul", "al", "Eb", ""},
	{"div", "al", "Eb", ""},
	{"idiv", "al", "Eb", ""},
	//
	{"test", "Ev", "Iv", ""},
	{"test", "Ev", "Iv", ""},
	{"not", "Ev", "", ""},
	{"neg", "Ev", "", ""},
	{"mul", "eax", "Ev", ""},
	{"imul", "eax", "Ev", ""},
	{"div", "eax", "Ev", ""},
	{"idiv", "eax", "Ev", ""}
};

static const x86_instruction x86_grp4[] = {
	{"inc", "", "", ""},
	{"dec", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""}
};

static const x86_instruction x86_grp5[] = {
	{"inc", "Ev", "", ""},
	{"dec", "Ev", "", ""},
	{"call", "Ev", "", ""},
	{"callf", "", "", ""},//don't know how to decode this yet
	{"jmp", "Ev", "", ""},
	{"jmp", "Ep", "", ""},
	{"push", "Ev", "", ""},
	{"", "", "", ""},
};

static const x86_instruction x86_grp6[] = {
	{"sldr", "", "", ""},
	{"str", "", "", ""},
	{"lldt", "", "", ""},
	{"ltr", "", "", ""},
	{"verr", "", "", ""},
	{"verw", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""}
};

static const x86_instruction x86_grp7[] = {
	{"sgdt", "Ms", "", ""},
	{"sidt", "Ms", "", ""},
	{"ldgt", "Ms", "", ""},
	{"lidt", "Ms", "", ""},
	{"smsw", "Ew", "", ""},
	{"", "", "", ""},
	{"lmsw", "Ew", "", ""},
	{"", "", "", ""}
};

static const x86_instruction x86_grp8[] = {
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"", "", "", ""},
	{"bt", "", "", ""},
	{"bts", "", "", ""},
	{"btr", "", "", ""},
	{"btc", "", "", ""},

};

static const x86_instruction* x86_groups[] = {
	x86_grp1, x86_grp2, x86_grp3, x86_grp4, x86_grp5, x86_grp6, x86_grp7, x86_grp8
};

#endif
