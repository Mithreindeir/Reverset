#include "x64lift.h"

ril_location *x64_operand_lift(char *operand)
{
	ril_location *loc = ril_loc_init();
	struct x64_assemble_op op = x64_assembler_type(operand);
	if (op.mode == X64_IMM || !strcmp(operand, "0")) {
		loc->addr = strtol(operand, NULL, 0);
		loc->type = RIL_ADDR;
	} else if (op.mode == X64_MODRM) {
		loc->type = RIL_MOFF;
		loc->nest = 1;
		struct x64_indirect indir;
		x64_retrieve_indirect(operand, &indir);
		ril_location *cur = NULL;
		ril_location *start = NULL;
		if (indir.base != -1) {
			if (!cur) {
				cur =
				x64_operand_lift(x64_get_register(indir.base, indir.addr_size,indir.rexb));
				start = cur;
			} else {
				cur->next =
				x64_operand_lift(x64_get_register(indir.base, indir.addr_size,indir.rexb));
				cur = cur->next;
			}
			cur->join_op = "+";
		}
		if (indir.index != -1) {
			if (!cur) {
				cur =
				x64_operand_lift(x64_get_register(indir.index, indir.addr_size,indir.rexx));
				start = cur;
			} else {
				cur->next =
				x64_operand_lift(x64_get_register(indir.index, indir.addr_size,indir.rexx));
				cur = cur->next;
			}
			cur->join_op = "*";
		}
		if (indir.scale != -1) {
			char buf[4];
			buf[0] = '0';
			buf[1] = 'x';
			buf[2] = 0x30 + indir.scale;
			buf[3] = 0;
			if (!cur) {
				cur =
				x64_operand_lift(buf);
				start = cur;
			} else {
				cur->next =
				x64_operand_lift(buf);
				cur = cur->next;
			}
		}
		if (indir.disp_size>=1) {
			char buf[16];
			if (indir.disp_size==1)
				indir.disp = 0x100-indir.disp;
			snprintf(buf,15,"%#lx", indir.disp);
			if (!cur) {
				cur =
				x64_operand_lift(buf);
				start = cur;
			} else {
				cur->next =
				x64_operand_lift(buf);
				cur = cur->next;
			}
		}
		loc->next = start;
	} else if (op.mode == X64_REG) {
		loc->type = RIL_REG;
		loc->reg = strdup(operand);
	}

	return loc;
}

ril_instruction *x64_instr_lift(r_disasm *dis)
{
	ril_instruction *instr = ril_instr_init();

	for (int i = 0; i < dis->num_operands; i++) {
		//Src is first operand
		if (i==0) {
			instr->nwrite++;
			if (!instr->write) {
				instr->write = malloc(sizeof(ril_location*));
			} else {
				instr->write = realloc(instr->write, sizeof(ril_location*)*instr->nwrite);
			}
			instr->write[instr->nwrite-1] = x64_operand_lift(dis->op[i]);
		} else {
			instr->nread++;
			if (!instr->read) {
				instr->read = malloc(sizeof(ril_location*));
			} else {
				instr->read = realloc(instr->read, sizeof(ril_location*)*instr->nread);
			}
			instr->read[instr->nread-1] = x64_operand_lift(dis->op[i]);
		}
	}
	instr->operation = strdup(dis->mnemonic);
	return instr;
}
