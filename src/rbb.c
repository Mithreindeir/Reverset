#include "rbb.h"

rbb *rbb_init(uint64_t start, uint64_t end)
{
	rbb * bb = malloc(sizeof(rbb));

	bb->size = end-start;
	bb->start = start;
	bb->end = end;

	bb->prev = NULL;
	bb->next = NULL;

	bb->num_prev = 0;
	bb->num_next = 0;

	return bb;
}

void rbb_destroy(rbb *bb)
{
	if (!bb) return;

	free(bb->prev);
	free(bb->next);
	free(bb);
}

void rbb_add(rbb *** basic_blocks, int *num_bb, rbb *bb)
{
	rbb **bbs = *basic_blocks;
	int nbb = *num_bb;
	nbb++;
	if (!bbs) {
		bbs = malloc(sizeof(rbb));
	} else {
		bbs = realloc(bbs, nbb*sizeof(rbb));
	}

	bbs[nbb-1] = bb;
	*num_bb = nbb;
	*basic_blocks = bbs;
}

rbb** rbb_anal(r_disassembler *disblr, r_branch*branches, int num_branches, int sidx, uint64_t s, uint64_t max,int*size)
{
	rbb**bbs = NULL;
	int nbb = 0;

	int lasts = sidx;
	for (int i = sidx; i < disblr->num_instructions; i++) {
		r_disasm *disas = disblr->instructions[i];
		if (disas->address > max) break;
		int ret = disas->metadata->type == r_tret;
		int bb_end = ret;
		int jump = 0;
		int jumpe = 0;
		for (int j = 0;!bb_end &&  j < num_branches; j++) {
			r_branch b = branches[j];
			jump = b.start == disas->address;
			jumpe = b.end == disas->address;
			if (b.dir && jump) {
				int tmp = jump;
				jump = jumpe;
				jumpe = tmp;
			}
			if (jump || (jumpe && lasts!=i))
				bb_end = 1;
		}
		if (bb_end) {
			rbb * bb=rbb_init(disblr->instructions[lasts]->address, disas->address + disas->used_bytes);
			rbb_add(&bbs, &nbb, bb);
			lasts = i+1;
		}
		if (ret) break;
	}

	*size = nbb;
	return bbs;
}
