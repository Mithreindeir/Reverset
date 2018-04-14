#include "ril.h"

ril_location *ril_loc_init()
{
	ril_location *loc = malloc(sizeof(ril_location));

	loc->type = RIL_NONE;
	loc->nest = 0;
	loc->next = NULL;
	loc->join_op = NULL;

	return loc;
}

void ril_loc_destroy(ril_location *loc)
{
	if (!loc) return;

	free(loc);
}

ril_instruction *ril_instr_init()
{
	ril_instruction *instr = malloc(sizeof(ril_instruction));

	instr->operation = NULL;
	instr->write=NULL, instr->read=NULL;
	instr->nwrite=0, instr->nread=0;

	return instr;
}

void ril_instr_destroy(ril_instruction *instr)
{
	if (!instr) return;

	free(instr);
}

void ril_loc_print(ril_location *loc)
{
	if (!loc) return;
	if (loc->type == RIL_MOFF) {
		writef("mem(");
		ril_loc_print(loc->next);
		writef(")");
	} else if (loc->type == RIL_REG) {
		writef("reg(%s)", loc->reg);
	} else if (loc->type == RIL_ADDR) {
		writef("imm(%#lx)", loc->addr);
	}
	if (!loc->nest && loc->next) {
		if (loc->join_op)
			writef("%s", loc->join_op);
		ril_loc_print(loc->next);
	}
}

void ril_instr_print(ril_instruction *instr)
{
	writef("OPERATION: %s\r\n", instr->operation);
	writef("WRITE:\r\n");
	for (int i = 0; i < instr->nwrite; i++) {
		ril_loc_print(instr->write[i]);
	}
	writef("\r\nREAD:\r\n");
	for (int i = 0; i < instr->nread; i++) {
		ril_loc_print(instr->read[i]);
	}
	writef("\r\n");
}
