#include "ssa.h"

ssa_vdb *ssa_vdb_init()
{
	ssa_vdb *db = malloc(sizeof(ssa_vdb));

	db->num_vp = 100;
	db->buckets = calloc(db->num_vp, sizeof(ssa_vp));
	db->num_ins = 0;

	return db;
}

void ssa_vdb_insert(ssa_vdb *db, char *var, int iter)
{
	unsigned int hash = hash_var(var);
	ssa_vp * nvp = ssa_vp_init(var, iter);
	ssa_vp_add(&db->buckets[hash % db->num_vp], nvp);
	db->num_ins++;
}

ssa_vp *ssa_vdb_lookup(ssa_vdb *db, const char * var)
{
	unsigned int hash = hash_var(var);
	ssa_vp *vp = ssa_vp_find(db->buckets[hash % db->num_vp], hash, var);
	return vp;
}

int ssa_vdb_get_iter(ssa_vdb *db, char *var)
{
	unsigned int hash = hash_var(var);
	ssa_vp *vp = ssa_vp_find(db->buckets[hash % db->num_vp], hash, var);
	return vp ? vp->iter : (ssa_vdb_insert(db, var, 0), 0);
}

int ssa_vdb_inc(ssa_vdb *db, char *var)
{
	unsigned int hash = hash_var(var);
	ssa_vp *vp = ssa_vp_find(db->buckets[hash % db->num_vp], hash, var);
	return vp ? ++vp->iter : (ssa_vdb_insert(db, var, 1), 1);
}

void ssa_vdb_remove(ssa_vdb *db, const char *var)
{

}

void ssa_vdb_destroy(ssa_vdb *db)
{
	for (int i = 0; i < db->num_vp; i++) {
		ssa_vp *cur=db->buckets[i],*last=NULL;
		while (cur) {
			last = cur;
			cur = cur->next;
			ssa_vp_destroy(last);
		}
	}
	free(db->buckets);
	free(db);
}

ssa_vp * ssa_vp_init(char *var, int iter)
{
	ssa_vp *vp = malloc(sizeof(ssa_vp));
	vp->var = var;
	vp->iter = iter;

	vp->hash = hash_var(var);
	vp->next = NULL;
	return  vp;
}

void ssa_vp_add(ssa_vp **head, ssa_vp *nvp)
{
	if (!(*head)) {
		*head = nvp;
		return;
	}
	ssa_vp *cur = *head;
	while (cur->next) cur = cur->next;
	cur->next = nvp;
}

ssa_vp *ssa_vp_find(ssa_vp *head, unsigned int hash, const char *var)
{
	while (head && head->hash != hash && !!strcmp(head->var, var))
		head = head->next;
	return head;
}

void ssa_vp_destroy(ssa_vp *vp)
{
	if (!vp) return;

	free(vp);
}

unsigned int hash_var(const char *var)
{
	unsigned int hash = 5381;
	char c;
	while ((c=*var++))
		hash = ((hash << 5) + hash) + (unsigned char)c;
	return hash;

}

void bb_clear(rbb *root)
{
	bb_set(root, -1);
	bb_set(root, 0);
}

void bb_set(rbb *root, int num)
{
	if (!root) return;
	root->drawn = num;
	for (int i = 0; i < root->num_next; i++) {
		if (root->next[i]->drawn != num)
			bb_set(root->next[i], num);
	}
}

int bb_height(rbb *bb)
{
	if (!bb) return 0;
	bb->drawn = 1;
	int max = 0, cur = 0;
	for (int i = 0; i < bb->num_next; i++) {
		if (bb->next[i]->drawn) continue;
		cur = bb_height(bb->next[i]);
		max = cur > max ? cur : max;
	}
	return max+1;
}

void cfg_to_ssa(rbb *root, ssa_vdb *db, rbb **bbs, int nbbs)
{
	/*Set used registers for each BB*/
	for (int i = 0; i < nbbs; i++) {
		bb_set_used(bbs[i]);
	}

	bb_clear(root);
	int height = bb_height(root);

	/*Rename all registers to create SSA. Level order tree traversal*/
	bb_clear(root);
	for (int i = 1; i <= height; i++) {
		bb_to_ssa(root, db, i);
	}
	bb_clear(root);

	/*Insert parameters to PHI functions*/
	for (int i = 0; i < nbbs; i++) {
		rbb *bb = bbs[i];
		if (bb->num_prev <= 1) continue;
		ril_instruction *cur = bb->instr;
		while (cur) {
			if (cur->op_type != RIL_PHI) break;
			bb_phi_upd(cur, bb->prev, bb->num_prev);
			cur = cur->next;
		}
	}
}

void bb_set_used(rbb *bb)
{
	if (!bb || !bb->instr) return;
	ril_instruction *cur = bb->instr;
	while (cur) {
		for (int i = 0; i < cur->nread; i++) {
			ril_instruction *cr = cur->read[i];
			if (cr->operand->type == RIL_REG) {
				int r1 = x_register_index(cr->operand->reg);
				char * reg = x64_general_registers[X_REG_BIN(r1)*4+3];
				rbb_set_var(bb, reg, 0);
			}
		}
		cur = cur->next;
	}
}

/*If 1 or more pred uses a var then the succ needs a phi node*/
int bb_phi_calc(rbb **pred, int num_pred, char *var)
{
	if (num_pred <= 1) return 0;
	for (int i = 0; i < num_pred; i++) {
		rbb *p = pred[i];
		for (int j = 0; j < p->num_var; j++) {
			if (!strcmp(p->vars[j], var)) {
				return 1;
			}
		}
	}

	return 0;
}

void bb_phi_upd(ril_instruction *phi, rbb **pred, int num_pred)
{
	if (!phi->write || !phi->nwrite) return;
	//test
	char buf[256];
	ril_instr_sn(buf, 256, phi);
	char *var = phi->write[0]->operand->reg;
	for (int i = 0; i < num_pred; i++) {
		rbb *p = pred[i];
		for (int j = 0; j < p->num_var; j++) {
			if (!strcmp(p->vars[j], var)) {
				phi->nread++;
				if (!phi->read)
					phi->read = malloc(sizeof(ril_instruction*));
				else
					phi->read=realloc(phi->read,sizeof(ril_instruction*)*phi->nread);
				ril_instruction *rn = ril_instr_init(RIL_OPER);
				rn->operand = ril_loc_init();
				rn->operand->type = RIL_REG;
				rn->operand->reg = var;
				rn->operand->iter = p->var_iters[j];
				phi->read[phi->nread-1] = rn;
			}
		}
	}
}

ril_instruction *bb_phi_insert(char *var, ssa_vdb *db)
{
	ril_instruction *instr = ril_instr_init(RIL_INSTR);

	instr->format = "$w = phi($r)";
	instr->mnem = "phi";
	instr->nwrite = 1;
	instr->op_type = RIL_PHI;
	instr->write = malloc(sizeof(ril_instruction*));
	instr->write[0] = ril_instr_init(RIL_OPER);
	instr->write[0]->operand = ril_loc_init();
	instr->write[0]->operand->type = RIL_REG;
	instr->write[0]->operand->reg = var;
	instr->write[0]->operand->iter = ssa_vdb_inc(db, var);

	return instr;
}

void bb_to_ssa(rbb *bb, ssa_vdb *db, int level)
{
	if (!bb || !bb->instr)
		return;

	if (level > 1) {
		for (int i = 0; i < bb->num_next; i++) {
			bb_to_ssa(bb->next[i], db, level-1);
		}
		return;
	}
	if (bb->drawn)
		return;
	ril_instruction *cur = bb->instr;
	/*Insert PHI Nodes for each used variable if needed*/
	for (int i = 0; i < bb->num_var; i++) {
		if (bb_phi_calc(bb->prev, bb->num_prev, bb->vars[i])) {
			ril_instruction *n = bb_phi_insert(bb->vars[i], db);
			n->next = bb->instr;
			bb->instr = n;
		}
	}

	bb->drawn = 1;
	while (cur) {
		for (int i = 0; i < cur->nread; i++) {
			ril_instruction *cr = cur->read[i];
			if (cr->operand->type == RIL_REG) {
				int r1 = x_register_index(cr->operand->reg);
				char * reg = x64_general_registers[X_REG_BIN(r1)*4+3];
				cr->operand->iter = ssa_vdb_get_iter(db, reg);
				rbb_set_var(bb, reg, cr->operand->iter);
			}
		}
		for (int i = 0; i < cur->nwrite; i++) {
			ril_instruction *cw = cur->write[i];
			if (cw->operand->type == RIL_REG) {
				int r1 = x_register_index(cw->operand->reg);
				char * reg = x64_general_registers[X_REG_BIN(r1)*4+3];
				cw->operand->iter = ssa_vdb_inc(db, reg);
				rbb_set_var(bb, reg, cw->operand->iter);
			}
		}
		cur = cur->next;
	}
}
