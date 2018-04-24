#include "x64lift.h"

ril_instruction *x64_operand_lift(char *operand)
{
	struct x64_assemble_op op = x64_assembler_type(operand);

	if (op.mode == X64_IMM || !strcmp(operand, "0")) {
		ril_instruction *loc = ril_instr_init(RIL_OPER);
		loc->value = strtol(operand, NULL, 0);
		loc->operand_type = RIL_VAL;
		return loc;
	} else if (op.mode == X64_MODRM) {
		ril_instruction *branch = ril_instr_init(RIL_INSTR);
		char fmt_buf[256];
		int iter = 0;
		iter+=snprintf(fmt_buf+iter,256-iter,"[");
		struct x64_indirect indir;
		x64_retrieve_indirect(operand, &indir);
		ril_instruction *cur = NULL;
		int sign = 1;
		if (indir.disp_size == 1 && indir.disp >= 0x80)
			sign = 0;
		char s = '+';
		if (!sign) s = '-';

		if (indir.base != -1) {
			cur = x64_operand_lift(x64_get_register(indir.base, indir.addr_size,indir.rexb));
			ril_instr_add(branch,cur,RIL_READ);
			iter+=snprintf(fmt_buf+iter,256-iter,"$r%d", branch->nread-1);
			if (indir.index != -1 || (indir.disp_size>=1 && indir.disp != 0))
				iter+=snprintf(fmt_buf+iter,256-iter,"%c", s);
		}
		if (indir.index != -1) {
			cur = x64_operand_lift(x64_get_register(indir.index, indir.addr_size,indir.rexx));
			ril_instr_add(branch, cur, RIL_READ);
			iter+=snprintf(fmt_buf+iter,256-iter,"$r%d", branch->nread-1);
		}
		if (indir.scale != -1) {
			char buf[4];
			buf[0] = '0';
			buf[1] = 'x';
			buf[2] = 0x30 + indir.scale;
			buf[3] = 0;
			cur =	x64_operand_lift(buf);
			ril_instr_add(branch,cur,RIL_READ);
			iter+=snprintf(fmt_buf+iter,256-iter,"*$r%d", branch->nread-1);
		}
		if (indir.disp_size>=1 && indir.disp != 0) {
			char buf[16];
			if (!sign)
				indir.disp = 0x100-indir.disp;
			snprintf(buf,15,"%#lx", indir.disp);
			cur = x64_operand_lift(buf);
			ril_instr_add(branch, cur, RIL_READ);
			iter+=snprintf(fmt_buf+iter,256-iter, "$r%d", branch->nread-1);
		}
		iter+=snprintf(fmt_buf+iter,256-iter, "]");
		branch->format = strdup(fmt_buf);
		return branch;
	} else if (op.mode == X64_REG) {
		ril_instruction *loc = ril_instr_init(RIL_OPER);
		loc->operand_type = RIL_REG;
		loc->reg = strdup(operand);
		return loc;
	}

	return NULL;
}
