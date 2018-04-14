#ifndef RIL_H
#define RIL_H

#include "../rdis.h"

/* Reverset Intermediate Language
 * Examples
 *
 * sub rsp, 0x10 			| x86
 * reg(rsp) -= imm(0x10) 		| ril
 *
 * mov eax, dword [ebp-0x4] 		| x86
 * reg(eax) = mem(reg(ebp) - imm(0x40))	| ril
 *
 * cmp dword [ebp-0x4], 0x9 		| x86
 * mem(reg(ebp) - imm(0x4)) == imm(0x9) | ril
 *
 * jle 0x62c 				| x86
 * <= addr(0x62c) 			| ril
 *
 * */

enum ril_loc_type {
	RIL_NONE,
	RIL_MOFF,
	RIL_REG,
	RIL_ADDR
};

typedef struct ril_location ril_location;
typedef struct ril_instruction ril_instruction;

struct ril_location {
	int type;
	int nest;
	union {
		char * reg;
		uint64_t offset;
		uint64_t addr;
	};
	struct ril_location *next;
	char *join_op;
};

struct ril_instruction {
	ril_location **write, **read;
	int nwrite, nread;
	char *operation;
};

ril_location *ril_loc_init();
void ril_loc_destroy(ril_location *loc);

ril_instruction *ril_instr_init();
void ril_instr_destroy(ril_instruction *instr);

void ril_loc_print(ril_location *loc);
void ril_instr_print(ril_instruction *instr);

ril_location *ril_operand_lift(char * operand);
ril_instruction *ril_instr_lift(r_disasm *dis);

#endif
