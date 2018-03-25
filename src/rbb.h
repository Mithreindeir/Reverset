#ifndef RBB_H
#define RBB_H

#include "rdis.h"
#include "rinfo.h"

/*Basic Blocks*/

rbb * rbb_init(uint64_t start, uint64_t end);
void rbb_destroy(rbb * bb);

void rbb_add(rbb *** basic_blocks, int *num_bb,  rbb * bb);

/*BB Analysis starts on a index to the disassembly and continues until a ret or end*/
rbb** rbb_anal(r_disassembler * disblr,r_branch *branches, int num_branches, int sidx, uint64_t s, uint64_t max, int*size);

void rbb_graph(rbb **bbs, int nbbs);

#endif
