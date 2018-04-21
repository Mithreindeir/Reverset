#ifndef SSA_H
#define SSA_H

#include "ril.h"
#include "../rinfo.h"

/*SSA Variable Database
 * Keeps track of the variable iterators*/
typedef struct ssa_vdb {
	struct ssa_vp ** buckets;
	int num_vp;
	int num_ins;
} ssa_vdb;

/* SSA Variable Pair*/
typedef struct ssa_vp {
	char * var;
	int iter;

	unsigned int hash;
	struct ssa_vp * next;
} ssa_vp;

ssa_vdb *ssa_vdb_init();
void ssa_vdb_insert(ssa_vdb *db, char *var, int iter);
ssa_vp *ssa_vdb_lookup(ssa_vdb *db, const char * var);
int ssa_vdb_get_iter(ssa_vdb *db, char *var);
int ssa_vdb_inc(ssa_vdb *db, char *var);
void ssa_vdb_remove(ssa_vdb *db, const char *var);
void ssa_vdb_destroy(ssa_vdb *db);

ssa_vp * ssa_vp_init(char *var, int iter);
void ssa_vp_add(ssa_vp **head, ssa_vp *nvp);
ssa_vp *ssa_vp_find(ssa_vp *head, unsigned int hash, const char *var);
void ssa_vp_destroy(ssa_vp *vp);

unsigned int hash_var(const char *var);

int bb_height(rbb *bb);
void bb_clear(rbb *root);
void bb_set(rbb *root, int num);
void cfg_to_ssa(rbb *root, ssa_vdb *db);
void bb_to_ssa(rbb *bb, ssa_vdb *db, int level);
void bb_ins_phi(rbb *bb, ssa_vdb *db);

#endif
