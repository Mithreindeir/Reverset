
enum OPERAND_TYPE
{
	REG,//Register, in the mr/m byte
	MRM,//Mod + R/M and sib and displacement bits specified location
	IMM, //Immediate value
	RPC, //Register Plus Command (For 1 byte instructions like 0x50 (push eax))
	REL8, //Relative one byte offset from current instruction
	NON //None
};


typedef struct opcode
{
	//Direction, size, immediate
	unsigned char v; //Value of opcode
	unsigned char mor;//Another byte for more info (base, or extended op)
	int d, s, e;//Direction, size, extended
	int arg1, arg2, arg3;
	char * name;
} opcode;

const opcode opcodes[] = {
	{0x00, 0x00, 0, 0, 0, MRM, REG, NON, "add"},
	{0x01, 0x00, 1, 1, 0, MRM, MRM, NON, "add"},
	{0x02, 0x00, 1, 0, 0, REG, MRM, NON, "add"},
	{0x03, 0x00, 1, 0, 0, REG, REG, NON, "add"},
	{0x28, 0x00, 0, 0, 0, MRM, REG, NON, "sub"},
	{0x29, 0x00, 0, 1, 0, MRM, REG, NON, "sub"},
	{0x2A, 0x00, 1, 0, 0, REG, MRM, NON, "sub"},
	{0x2B, 0x00, 1, 1, 0, REG, MRM, NON, "sub"}, 
	{0x50, 0x50, 0, 1, 0, RPC, NON, NON, "push"},
	{0x51, 0x50, 0, 1, 0, RPC, NON, NON, "push"},
	{0x52, 0x50, 0, 1, 0, RPC, NON, NON, "push"},
	{0x53, 0x50, 0, 1, 0, RPC, NON, NON, "push"},
	{0x54, 0x50, 0, 1, 0, RPC, NON, NON, "push"},
	{0x55, 0x50, 0, 1, 0, RPC, NON, NON, "push"},
	{0x56, 0x50, 0, 1, 0, RPC, NON, NON, "push"},
	{0x57, 0x50, 0, 1, 0, RPC, NON, NON, "push"},
	{0x58, 0x58, 0, 1, 0, RPC, NON, NON, "pop"},
	{0x59, 0x58, 0, 1, 0, RPC, NON, NON, "pop"},
	{0x5a, 0x58, 0, 1, 0, RPC, NON, NON, "pop"},
	{0x5b, 0x58, 0, 1, 0, RPC, NON, NON, "pop"},
	{0x5c, 0x58, 0, 1, 0, RPC, NON, NON, "pop"},
	{0x5d, 0x58, 0, 1, 0, RPC, NON, NON, "pop"},
	{0x5e, 0x00, 0, 1, 0, RPC, NON, NON, "pop"},
	{0x5f, 0x00, 0, 1, 0, RPC, NON, NON, "pop"},
	{0x88, 0x00, 0, 0, 0, MRM, REG, NON, "mov"},
	{0x89, 0x00, 0, 1, 0, MRM, REG, NON, "mov"},
	{0x8a, 0x00, 0, 0, 0, REG, REG, NON, "mov"},
	{0x8b, 0x00, 1, 1, 0, MRM, REG, NON, "mov"},
	{0xb8, 0x00, 0, 0, 0, MRM, IMM, NON, "mov"},
	{0x74, 0x00, 0, 0, 0, REL8, NON, NON, "je"},
	{0x75, 0x00, 0, 0, 0, REL8, NON, NON, "jnz"},
	{0x76, 0x00, 0, 0, 0, REL8, NON, NON, "jbe"},
	{0x77, 0x00, 0, 0, 0, REL8, NON, NON, "jnbe"},
	{0x78, 0x00, 0, 0, 0, REL8, NON, NON, "js"},
	{0x79, 0x00, 0, 0, 0, REL8, NON, NON, "jns"},
	{0x7a, 0x00, 0, 0, 0, REL8, NON, NON, "jp"},
	{0x7b, 0x00, 0, 0, 0, REL8, NON, NON, "jnp"},
	{0x7c, 0x00, 0, 0, 0, REL8, NON, NON, "jl"},
	{0x7d, 0x00, 0, 0, 0, REL8, NON, NON, "jge"},
	{0x7e, 0x00, 0, 0, 0, REL8, NON, NON, "jle"},
	{0x7f, 0x00, 0, 0, 0, REL8, NON, NON, "jg"},
	{0x90, 0x00, 0, 0, 0, NON, NON, NON, "nop"},
	{0x83, 0x00, 0, 1, 1, MRM, IMM, NON, "add"},
	{0x83, 0x01, 0, 1, 1, MRM, IMM, NON, "add"},
	{0x83, 0x02, 0, 1, 1, MRM, IMM, NON, "adc"},
	{0x83, 0x03, 0, 1, 1, MRM, IMM, NON, "sbb"},
	{0x83, 0x04, 0, 1, 1, MRM, IMM, NON, "and"},
	{0x83, 0x05, 0, 1, 1, MRM, IMM, NON, "sub"},
	{0x83, 0x06, 0, 1, 1, MRM, IMM, NON, "xor"},
	{0x83, 0x07, 0, 1, 1, MRM, IMM, NON, "cmp"},
	{0x80, 0x00, 0, 0, 1, MRM, IMM, NON, "add"},
	{0x80, 0x01, 0, 0, 1, MRM, IMM, NON, "or"},
	{0x80, 0x02, 0, 0, 1, MRM, IMM, NON, "adc"},
	{0x80, 0x03, 0, 0, 1, MRM, IMM, NON, "sbb"},
	{0x80, 0x04, 0, 0, 1, MRM, IMM, NON, "and"},
	{0x80, 0x05, 0, 0, 1, MRM, IMM, NON, "sub"},
	{0x80, 0x06, 0, 0, 1, MRM, IMM, NON, "or"},
	{0x80, 0x07, 0, 0, 1, MRM, IMM, NON, "cmp"},
	{0x85, 0x00, 1, 1, 0, MRM, REG, NON, "test"},
	{0x8d, 0x00, 0, 1, 0, REG, MRM, NON, "lea"},
	{0xFE, 0x00, 0, 0, 1, MRM, NON, NON, "inc"},
	{0xFE, 0x01, 0, 0, 1, MRM, NON, NON, "dec"},
	{0xFF, 0x00, 0, 1, 1, MRM, NON, NON, "inc"},
	{0xFF, 0x01, 0, 1, 1, MRM, NON, NON, "dec"},
	{0xFF, 0x02, 0, 1, 1, MRM, NON, NON, "call"},
	{0xFF, 0x03, 0, 1, 1, MRM, NON, NON, "callf"},
	{0xFF, 0x04, 0, 1, 1, MRM, NON, NON, "jmp"},
	{0xFF, 0x05, 0, 1, 1, MRM, NON, NON, "jmpf"},
	{0xFF, 0x06, 0, 1, 1, MRM, NON, NON, "push"},
	
};
