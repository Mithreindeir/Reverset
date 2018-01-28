#ifndef _ARM_INSTRUCTIONS_H
#define _ARM_INSTRUCTIONS_H

enum arm_instruction_type
{
	ARM_DATA_PROCESSING,//00I OPCODE S Rn Rs OPERAND-2
	ARM_MULT,		//Multiply 00000AS Rd Rn Rs 1001 Rm
	ARM_LONG_MULT,	//Long Multiply 00001UAS Rd High Rd Low RS 1001 Rm
	ARM_SWAP,		//Swap 00010B00 Rn Rd 00001001 Rm
	ARM_LDSTBW,		//Load/Store byte/word 01IPUBWL Rn Rd Offset
	ARM_LDSTM,		//Load/Store Multiple 100PuBWL Rn REGISTER LIST
	ARM_HWTIMM,		//Halfword Transfer Imm off 000PU1WL Rn Rd OFFSET1 1 S H 1 OFFSET2
	ARM_HWTR,		//Halfword Transfre Reg Off 000PU0WL Rn Rd 00001SH1 Rm
	ARM_BRANCH,		//Branch 101L Branch OFfset
	ARM_BREX,		//Branch Exchange 0001001011111111111110001Rn
	ARM_COXFER,		//Coprocessor data xfer Condition 110PUNWL Rn CRd CPNum Offset
	ARM_COOP,		//Coprocessor data op  Condition 1110 OP-1 CRn CRd CPNum OP-2 0 CRm
	ARM_COREG,		//Coprocessor reg xfer Condition ---- OP-1 L Crn Rd CPNum OP-2 1 CRm
	ARM_INTERRUPT	//Software interrupt. Condition 1 1 1 1 SWI NUMBER 
};
//Condition Field
enum arm_condition
{
	ARM_EQZ,	//0000 EQ Z set
	ARM_NEZ,	//0001 NE Z clear
	ARM_HSCS,	//0010 C set
	ARM_LOCC,	//0011 C clear
	ARM_MIN,	//0100 N set
	ARM_PLN,	//0101 N clear 
	ARM_VSV,	//0110 V set
	ARM_VCV,	//0111 V clear
	ARM_HIC,	//1000 C set and Z clear
	ARM_LSC,	//1001 C clear or Z (set unsigned lower or same)
	ARM_GEN,	//1010 N set and V set, or N clear and V clear
	ARM_LTN,	//1011 N set and V clear or N clear and V set
	ARM_GTZ,	//1100 Z clear and either N set and V set or N clear and V set
	ARM_LEZ,	//1101 Z set and N set and V clear or N clear and V set
	ARM_AL,		//1110 AL - Reserved
	ARM_NV		//1111 NV - Reserved
};

static char * arm_cond_str[] = {
	"eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"
};

typedef struct arm_instruction {
	char * mnemonic;
} arm_instruction;

static arm_instruction arm_data_instruction[] = {
	{"and"},
	{"eor"},
	{"sub"},
	{"rsb"},
	{"add"},
	{"adc"},
	{"sbc"},
	{"rsc"},
	{"tst"},
	{"teq"},
	{"cmp"},
	{"cmn"},
	{"orr"},
	{"mov"},
	{"bic"},
	{"mvn"}
};

#endif