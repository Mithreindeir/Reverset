enum OPERAND_TYPE
{
	REG,
	MRM,
	IMM8,
	IMM32,
	RPC,
	REL8,
	REL1632,
	NON
};

enum OPCODE_ACTION
{
	ASN,	//Assigment (mov, lea...)
	OPR,	//Operation (add, sub, mul, div...)
	FLW,	//Program Flow (jmp, call...)
	MEM,	//Memory (push, pop...)
	CMP,
	COND,
	OTR	//Other
};

typedef struct condition
{
	char * symbol;		//Opposite symbol, because jump "skips" over things, so conditions are to not skip it
	char * name;		//Jump instruction attributes to it
} condition;

static const condition conditions[] = {
	{">=", "jl"},
	{">", "jle"},
	{"<=", "jg"},
	{"<", "jge"},
	{"==", "jne"},
	{"!=", "je"}
};
typedef struct action
{
	enum OPCODE_ACTION op_action;
	char * symbol;
	char * symbol_indir;
	char * name;
} action;

static const action actions[] = {
	{ASN, "=", "", "mov"},
	{OPR, "+=", "+", "add"},
	{OPR, "-=", "-",  "sub"},
	{OPR, "&=", "&", "and"},
	{OPR, "|=", "|", "or"},
	{OPR, "!=", "!", "not"},
	{OPR, "^=", "^", "xor"},
	{FLW, "jump", "jump", "jmp"},
	{FLW, "jump less than or equal to", "jump less than or equal to", "jle"},
	{FLW, "jump equal", "jump equal", "je"},
	{FLW, "jump not equal", "jump not equal", "jne"},
	{FLW, "jump greater than or equal to", "jump greater than or equal to", "jge"},
	{FLW, "jump greater than", "jump greater than", "jg"},
	{FLW, "jump not signed", "jump not signed", "jns"},
	{FLW, "jump signed", "jump signed", "js"},
	{FLW, "= &", "&", "lea"},
	{OPR, "<<=", "<<", "shl"},
	{OPR, ">>=", ">>", "shr"},
	{OPR, ">>=", ">>", "sar"},
	{FLW, "()", "()", "call"},
	{FLW, "return", "", "ret"},
	{MEM, "", "", "push"},
	{MEM, "", "", "pop"},
	{CMP, "cmp", "cmp", "cmp"},
	//Include conditions
	{COND, ">=", ">=", "l"},
	{COND, ">", ">", "le"},
	{COND, "<=", "<=", "g"},
	{COND, "<", "<", "ge"},
	{COND,"==", "==", "ne"},
	{COND, "!=", "!=", "e"},
	{OTR, "", "", "non"}
};

typedef struct opcode
{
	unsigned char v;
	unsigned char mor;
	int d, s, e;
	int arg1, arg2, arg3;
	char * name;
	int action;
} opcode;

static const opcode opcodes[] = {
	{0x00, 0x00, 0, 0, 0, MRM, REG, NON, "add"},
	{0x01, 0x00, 1, 1, 0, MRM, REG, NON, "add"},
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
	{0x5e, 0x58, 0, 1, 0, RPC, NON, NON, "pop"},
	{0x5f, 0x58, 0, 1, 0, RPC, NON, NON, "pop"},
	{0x88, 0x00, 0, 0, 0, MRM, REG, NON, "mov"},
	{0x89, 0x00, 0, 1, 0, MRM, REG, NON, "mov"},
	{0x8a, 0x00, 0, 0, 0, REG, REG, NON, "mov"},
	{0x8b, 0x00, 1, 1, 0, REG, MRM, NON, "mov"},
	//{0xb8, 0x00, 0, 0, 0, MRM, IMM, NON, "mov"},
	{0x74, 0x00, 0, 0, 0, REL8, NON, NON, "je"},
	{0x75, 0x00, 0, 0, 0, REL8, NON, NON, "jne"},
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
	{0x83, 0x00, 0, 1, 1, MRM, IMM8, NON, "add"},
	{0x83, 0x01, 0, 1, 1, MRM, IMM8, NON, "add"},
	{0x83, 0x02, 0, 1, 1, MRM, IMM8, NON, "adc"},
	{0x83, 0x03, 0, 1, 1, MRM, IMM8, NON, "sbb"},
	{0x83, 0x04, 0, 1, 1, MRM, IMM8, NON, "and"},
	{0x83, 0x05, 0, 1, 1, MRM, IMM8, NON, "sub"},
	{0x83, 0x06, 0, 1, 1, MRM, IMM8, NON, "xor"},
	{0x83, 0x07, 0, 1, 1, MRM, IMM8, NON, "cmp"},
	{0x80, 0x00, 0, 0, 1, MRM, IMM8, NON, "add"},
	{0x80, 0x01, 0, 0, 1, MRM, IMM8, NON, "or"},
	{0x80, 0x02, 0, 0, 1, MRM, IMM8, NON, "adc"},
	{0x80, 0x03, 0, 0, 1, MRM, IMM8, NON, "sbb"},
	{0x80, 0x04, 0, 0, 1, MRM, IMM8, NON, "and"},
	{0x80, 0x05, 0, 0, 1, MRM, IMM8, NON, "sub"},
	{0x80, 0x06, 0, 0, 1, MRM, IMM8, NON, "or"},
	{0x80, 0x07, 0, 0, 1, MRM, IMM8, NON, "cmp"},
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
	{0xC0, 0x00, 0, 0, 1, MRM, IMM8, NON, "rol"},
	{0xC0, 0x01, 0, 0, 1, MRM, IMM8, NON, "ror"},
	{0xC0, 0x02, 0, 0, 1, MRM, IMM8, NON, "rcl"},
	{0xC0, 0x03, 0, 0, 1, MRM, IMM8, NON, "rcr"},
	{0xC0, 0x04, 0, 0, 1, MRM, IMM8, NON, "shl"},
	{0xC0, 0x05, 0, 0, 1, MRM, IMM8, NON, "shr"},
	{0xC0, 0x06, 0, 0, 1, MRM, IMM8, NON, "sal"},	
	{0xC0, 0x07, 0, 0, 1, MRM, IMM8, NON, "sar"},
	{0xC1, 0x00, 0, 1, 1, MRM, IMM8, NON, "rol"},
	{0xC1, 0x01, 0, 1, 1, MRM, IMM8, NON, "ror"},
	{0xC1, 0x02, 0, 1, 1, MRM, IMM8, NON, "rcl"},
	{0xC1, 0x03, 0, 1, 1, MRM, IMM8, NON, "rcr"},
	{0xC1, 0x04, 0, 1, 1, MRM, IMM8, NON, "shl"},
	{0xC1, 0x05, 0, 1, 1, MRM, IMM8, NON, "shr"},
	{0xC1, 0x06, 0, 1, 1, MRM, IMM8, NON, "sal"},	
	{0xC1, 0x07, 0, 1, 1, MRM, IMM8, NON, "sar"},
	{0xC6, 0x00, 0, 0, 0, MRM, IMM8, NON, "mov"},
	{0xC7, 0x00, 0, 1, 0, MRM, IMM32, NON, "mov"},
	{0xC3, 0x00, 0, 0, 0, NON, NON, NON, "ret"},
	{0xB0, 0xB0, 0, 0, 0, RPC, IMM8, NON, "mov"},
	{0xB1, 0xB0, 0, 0, 0, RPC, IMM8, NON, "mov"},
	{0xB2, 0xB0, 0, 0, 0, RPC, IMM8, NON, "mov"},
	{0xB3, 0xB0, 0, 0, 0, RPC, IMM8, NON, "mov"},
	{0xB4, 0xB0, 0, 0, 0, RPC, IMM8, NON, "mov"},
	{0xB5, 0xB0, 0, 0, 0, RPC, IMM8, NON, "mov"},
	{0xB6, 0xB0, 0, 0, 0, RPC, IMM8, NON, "mov"},
	{0xB7, 0xB0, 0, 0, 0, RPC, IMM8, NON, "mov"},
	{0xB8, 0xB8, 0, 1, 0, RPC, IMM32, NON, "mov"},
	{0xB9, 0xB8, 0, 1, 0, RPC, IMM32, NON, "mov"},
	{0xBA, 0xB8, 0, 1, 0, RPC, IMM32, NON, "mov"},
	{0xBB, 0xB8, 0, 1, 0, RPC, IMM32, NON, "mov"},
	{0xBC, 0xB8, 0, 1, 0, RPC, IMM32, NON, "mov"},
	{0xBD, 0xB8, 0, 1, 0, RPC, IMM32, NON, "mov"},
	{0xBF, 0xB8, 0, 1, 0, RPC, IMM32, NON, "mov"},
	{0x8D, 0x00, 0, 1, 0, RPC, IMM32, NON, "lea"},
	{0xE8, 0x00, 0, 1, 0, REL1632, NON, NON, "call"},
	{0xE9, 0x00, 0, 1, 0, REL1632, NON, NON, "jm"},
	{0xEB, 0x00, 0, 0, 0, REL8, NON, NON, "jmp"},
	{0x40, 0x040, 0, 1, 0, RPC, NON, NON, "inc"},
	{0x41, 0x040, 0, 1, 0, RPC, NON, NON, "inc"},
	{0x42, 0x040, 0, 1, 0, RPC, NON, NON, "inc"},
	{0x43, 0x040, 0, 1, 0, RPC, NON, NON, "inc"},
	{0x44, 0x040, 0, 1, 0, RPC, NON, NON, "inc"},
	{0x45, 0x040, 0, 1, 0, RPC, NON, NON, "inc"},
	{0x46, 0x040, 0, 1, 0, RPC, NON, NON, "inc"},
	{0x47, 0x040, 0, 1, 0, RPC, NON, NON, "inc"},
	{0x48, 0x048, 0, 1, 0, RPC, NON, NON, "dec"},
	{0x49, 0x048, 0, 1, 0, RPC, NON, NON, "dec"},
	{0x4a, 0x048, 0, 1, 0, RPC, NON, NON, "dec"},
	{0x4b, 0x048, 0, 1, 0, RPC, NON, NON, "dec"},
	{0x4c, 0x048, 0, 1, 0, RPC, NON, NON, "dec"},
	{0x4d, 0x048, 0, 1, 0, RPC, NON, NON, "dec"},
	{0x4e, 0x048, 0, 1, 0, RPC, NON, NON, "dec"},
	{0x4f, 0x048, 0, 1, 0, RPC, NON, NON, "dec"},
	{0x33, 0x00, 1, 1, 0, REG, MRM, NON, "xor"}
	
};
