#include "dec.h"

void ssa_expr_prop(rbb *bb)
{
	if (!bb || !bb->instr) return;
	/*Start off just propogating MOV instructions*/
	ril_instruction *cur = bb->instr;
	while (cur) {
		int good = 0;
		if (cur->action == RIL_ASSIGN)
			good = ssa_reduce(cur, &ssa_asn_reduce);
		else if (cur->action == RIL_ADD_ASSIGN)
			good = ssa_reduce(cur, &ssa_add_reduce);
		else if (cur->action == RIL_SUB_ASSIGN)
			good = ssa_reduce(cur, &ssa_sub_reduce);
		else if (cur->action == RIL_MUL_ASSIGN)
			good = ssa_reduce(cur, &ssa_mul_reduce);
		else if (cur->action == RIL_MEM_ASSIGN)
			good = ssa_reduce(cur, &ssa_ref_reduce);

		if (good)
			cur->comment = 1;
		cur = cur->next;
	}
}

int ssa_reduce(ril_instruction *cur, ssa_op_reduce reduce)
{
	if (cur->nwrite <= 0 || cur->nread <= 0)
		return 0;
	if (cur->write[0]->operand->type != RIL_REG)
		return 0;
	ril_instruction *iter = cur;
	char *reg = cur->write[0]->operand->reg;
	int idx = x_register_index(reg);
	idx = X_REG_BIN(idx);
	int regi = cur->write[0]->operand->iter;
	while (iter) {
		for (int i = 0; i < iter->nread; i++) {
			if (!iter->read[i])
				continue;
			if (iter->read[i]->type != RIL_OPER)
				continue;
			if (iter->read[i]->operand->type != RIL_REG)
				continue;
			int idx2 = x_register_index(iter->read[i]->operand->reg);
			idx2 = X_REG_BIN(idx2);
			if (idx2==idx) {
				if (iter->read[i]->operand->iter == regi) {
					reduce(cur, &iter->read[i]);
					//iter->read[i] = cur->read[0];
				}
			}
		}
		iter = iter->next;
	}
	return 1;
}

void ssa_asn_reduce(ril_instruction *cur, ril_instruction **operand)
{
	ril_instr_destroy(*operand);
	(*operand) = ril_instr_dup(cur->read[0]);
}

void ssa_ref_reduce(ril_instruction *cur, ril_instruction **operand)
{
	ril_instr_destroy(*operand);
	ril_instruction *rep = ril_instr_dup(cur);
	rep->format = "&$r0";
	(*operand) = rep;
}

void ssa_add_reduce(ril_instruction *cur, ril_instruction **operand)
{
	ril_instr_destroy(*operand);
	ril_instruction *rep = ril_instr_dup(cur);
	rep->format = "($r0 + $r1)";
	(*operand) = rep;
}

void ssa_sub_reduce(ril_instruction *cur, ril_instruction **operand)
{
	ril_instr_destroy(*operand);
	ril_instruction *rep = ril_instr_dup(cur);
	rep->format = "($r0 - $r1)";
	(*operand) = rep;
}

void ssa_mul_reduce(ril_instruction *cur, ril_instruction **operand)
{
	ril_instr_destroy(*operand);
	ril_instruction *rep = ril_instr_dup(cur);
	rep->next = NULL;
	rep->format = "($r0 * $r1)";
	(*operand) = rep;
}
