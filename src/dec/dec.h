#ifndef DEC_H
#define DEC_H

#include "ril.h"
#include "../rbb.h"

/*Decompiler
 *Takes input as CFG of SSA instructions
 *Steps:
 * - Aggressive expression propogation
 * - Overflowing registers to memory
 * - Memory location renaming
 * - CFG Analysis to determine loops/conditional statements
 * - Type propogation
 * - ABI/Calling conv dependent transformations (eg: using eax as return value)
 * - Print as formatted C code
 * */

typedef ril_instruction*(*ssa_op_reduce)(ril_instruction *cur);
void ssa_expr_prop(rbb * bb);
int ssa_reduce(ril_instruction *cur, ssa_op_reduce reduce);
 ril_instruction *ssa_instr_reduce(ril_instruction *cur, ril_instruction *iter, ssa_op_reduce reduce);
 ril_instruction *ssa_asn_reduce(ril_instruction *cur);
 ril_instruction *ssa_ref_reduce(ril_instruction *cur);
 ril_instruction *ssa_add_reduce(ril_instruction *cur);
 ril_instruction *ssa_sub_reduce(ril_instruction *cur);
 ril_instruction *ssa_mul_reduce(ril_instruction *cur);

#endif
