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

void cfg_to_ssa(rbb *root, ssa_vdb *db)
{
	bb_clear(root);
	int height = bb_height(root);
	bb_clear(root);
	for (int i = 1; i <= height; i++) {
		bb_to_ssa(root, db, i);
	}
	bb_clear(root);
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
	bb->drawn = 1;
	ril_instruction *cur = bb->instr;
	while (cur) {
		for (int i = 0; i < cur->nread; i++) {
			ril_instruction *cr = cur->read[i];
			if (cr->operand->type == RIL_REG) {
				int r1 = x_register_index(cr->operand->reg);
				char * reg = x64_general_registers[X_REG_BIN(r1)*4+3];
				cr->operand->iter = ssa_vdb_get_iter(db, reg);
			}
		}
		for (int i = 0; i < cur->nwrite; i++) {
			ril_instruction *cw = cur->write[i];
			if (cw->operand->type == RIL_REG) {
				int r1 = x_register_index(cw->operand->reg);
				char * reg = x64_general_registers[X_REG_BIN(r1)*4+3];
				cw->operand->iter = ssa_vdb_inc(db, reg);
			}

		}
		cur = cur->next;
	}
}

void bb_ins_phi(rbb *bb, ssa_vdb *db)
{
	if (bb) return;

}
