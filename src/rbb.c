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

	uint64_t *pedge = NULL;
	uint64_t *nedge = NULL;
	int num_edges = 0;

	int lasts = sidx;
	int lbbend = 0;
	for (int i = sidx; i < disblr->num_instructions; i++) {
		r_disasm *disas = disblr->instructions[i];
		if (disas->address > max) break;
		int ret = disas->metadata->type == r_tret;
		int bb_end = ret;
		int jump = 0;
		int jumpe = 0;
		int include = 1;
		for (int j = 0;!bb_end && j < num_branches; j++) {
			r_branch b = branches[j];
			int s = b.dir?b.end:b.start;
			int e = b.dir?b.start:b.end;
			jump = s == disas->address;
			jumpe = e == disas->address;
			if (jump || (jumpe && !lbbend))
				include=!jumpe, bb_end = 1;
			//Add edge
			if (jump) {
				num_edges++;
				if (num_edges==1) {
					pedge = malloc(sizeof(uint64_t)*num_edges);
					nedge = malloc(sizeof(uint64_t)*num_edges);
				} else {
					pedge=realloc(pedge,sizeof(uint64_t)*num_edges);
					nedge=realloc(nedge,sizeof(uint64_t)*num_edges);
				}
				pedge[num_edges-1]=s;
				nedge[num_edges-1]=e;
			}
			int uncjmp = b.conditional&&jump;
			if (!uncjmp&&bb_end&&(i+1)<disblr->num_instructions) {
				num_edges++;
				if (num_edges==1) {
					pedge = malloc(sizeof(uint64_t)*num_edges);
					nedge = malloc(sizeof(uint64_t)*num_edges);
				} else {
					pedge=realloc(pedge,sizeof(uint64_t)*num_edges);
					nedge=realloc(nedge,sizeof(uint64_t)*num_edges);
				}
				if (include || (i<=0)) {
					pedge[num_edges-1]=disas->address;
					nedge[num_edges-1]=disblr->instructions[i+1]->address;
					//nedge[num_edges-1]=disblr->instructions[i+1]->address+disblr->instructions[i+1]->used_bytes;
				} else {
					pedge[num_edges-1]=disblr->instructions[i-1]->address;
					nedge[num_edges-1]=disas->address;
				}
			}
		}
		if (bb_end) {
			uint64_t end = disas->address + (include?disas->used_bytes:0);
			rbb * bb=rbb_init(disblr->instructions[lasts]->address, end);
			rbb_add(&bbs, &nbb, bb);
			lasts = i+include;
		}
		lbbend = bb_end;
		if (ret) break;
	}
	/*After calculating all basic blocks, attempt to connect edges using jumps*/
	for (int i = 0; i < num_edges; i++) {
		rbb *next=NULL,*prev=NULL;
		for (int j = 0; j < nbb; j++) {
			if (pedge[i] >= bbs[j]->start && pedge[i] < bbs[j]->end) {
				prev=bbs[j];
				break;
			}
		}
		for (int j = 0; j < nbb; j++) {
			if (nedge[i] >= bbs[j]->start && nedge[i] < bbs[j]->end) {
				next=bbs[j];
			}
		}
		if (!next || !prev || (next==prev)) {
			continue;
		}
		prev->num_next++;
		next->num_prev++;
		if (!next->prev) {
			next->prev=malloc(sizeof(rbb*));
		} else {
			next->prev=realloc(next->prev,sizeof(rbb*)*next->num_prev);
		}
		if (!prev->next) {
			prev->next=malloc(sizeof(rbb*));
		} else {
			prev->next=realloc(prev->next,sizeof(rbb*)*prev->num_next);
		}
		next->prev[next->num_prev-1] = prev;
		prev->next[prev->num_next-1] = next;
	}
	free(nedge);
	free(pedge);
	*size = nbb;
	return bbs;
}

void rbb_graph(rbb **bbs, int nbbs)
{
	if (nbbs) {
		writef("digraph F {\r\n");
	}
	for (int k = 0; k < nbbs; k++) {
		for (int l = 0; l < bbs[k]->num_next; l++)
			writef("\t\"(%#lx-%#lx)\" -> \"(%#lx-%#lx)\"\r\n", bbs[k]->start, bbs[k]->end, bbs[k]->next[l]->start, bbs[k]->next[l]->end);
	}
	if (nbbs)
		writef("}\r\n");
}
