#include "ril.h"

ril_instruction *ril_instr_init(int type)
{
	ril_instruction *instr = malloc(sizeof(ril_instruction));

	instr->comment = 0;
	instr->type = type;
	if (type == RIL_INSTR) {
		instr->action = RIL_NOP;
		instr->op_type = 0;
		instr->format = NULL;
		instr->write=NULL, instr->read=NULL;
		instr->nwrite=0, instr->nread=0;
	} else if (type == RIL_OPER) {
		instr->operand_type = RIL_NONE;
		instr->reg = NULL;
		instr->value = 0;
		instr->ssa_iter = -1;
	}
	instr->next = NULL;

	return instr;
}

void ril_instr_destroy(ril_instruction *instr)
{
	if (!instr) return;
	if (instr->type == RIL_OPER) {
		if (instr->operand_type == RIL_REG)
			free(instr->reg);
		free(instr);
		return;
	}

	for (int i = 0; i < instr->nwrite; i++) {
		ril_instr_destroy(instr->write[i]);
	}

	for (int i = 0; i < instr->nread; i++) {
		ril_instr_destroy(instr->read[i]);
	}

	free(instr->format);
	free(instr->write);
	free(instr->read);
	free(instr);
}

void ril_instr_add(ril_instruction *branch, ril_instruction *leaf, int type)
{
	if (!branch || branch->type != RIL_INSTR) return;
	if (type == RIL_READ) {
		branch->nread++;
		if (!branch->read) {
			branch->read = malloc(sizeof(ril_instruction*)*branch->nread);
		} else {
			branch->read = realloc(branch->read,sizeof(ril_instruction*)*branch->nread);
		}
		branch->read[branch->nread-1] = leaf;
	} else if (type == RIL_WRITE) {
		branch->nwrite++;
		if (!branch->write) {
			branch->write = malloc(sizeof(ril_instruction*)*branch->nwrite);
		} else {
			branch->write = realloc(branch->write,sizeof(ril_instruction*)*branch->nwrite);
		}
		branch->write[branch->nwrite-1] = leaf;
	}
}

ril_instruction *ril_instr_dup(ril_instruction *instr)
{
	if (!instr) return NULL;
	ril_instruction *dup = ril_instr_init(instr->type);
	if (instr->type == RIL_INSTR) {
		dup->format = strdup(instr->format);
		dup->action = instr->action;
		dup->op_type = instr->op_type;
		dup->nread = instr->nread;
		dup->nwrite = instr->nwrite;
		if (instr->nwrite)
			dup->write=malloc(sizeof(ril_instruction*)*dup->nwrite);
		if (instr->nread)
			dup->read=malloc(sizeof(ril_instruction*)*dup->nread);

		for (int j = 0; j < instr->nread; j++) {
			dup->read[j] = ril_instr_dup(instr->read[j]);
		}
		for (int j = 0; j < instr->nwrite; j++) {
			dup->write[j] = ril_instr_dup(instr->write[j]);
		}
	} else if (instr->type == RIL_OPER) {
		if (instr->operand_type == RIL_REG) {
			dup->reg = strdup(instr->reg);
		} else if (instr->operand_type == RIL_VAL) {
			dup->value = instr->value;
		}
		dup->operand_type = instr->operand_type;
		dup->ssa_iter = instr->ssa_iter;
	}
	dup->next = instr->next;
	return dup;
}

int ril_instr_sn(char *buf, int max, ril_instruction *instr)
{
	if (!instr) return 0;
	int iter = 0;
	if (instr->type == RIL_OPER) {
		if (instr->operand_type == RIL_REG) {
			iter += snprintf(buf+iter, max-iter, "%s_%d", instr->reg, instr->ssa_iter);
		} else if (instr->operand_type == RIL_VAL) {
			iter += snprintf(buf+iter, max-iter, "%#lx", instr->value);
		}
		return iter;
	}
	if (!instr->format) {
		return iter;
	}
	if (instr->comment) {
		//iter += snprintf(buf+iter, max-iter, "//");
	}
	int flen = strlen(instr->format);
	int flast = 0;
	for (int i = 0; i < flen; i++) {
		if (instr->format[i]=='$') {
			if (i-flast) {
				iter += snprintf(buf+iter, max-iter, "%*.*s", i-flast, i-flast, instr->format+flast);
			}
			int type = instr->format[i+1]=='r'?RIL_READ:RIL_WRITE;
			int num = (i+2)<flen ? (signed int)instr->format[i+2]-0x30 : -1;
			if (num >=0 && num < 10) {
				i++;
				if (type == RIL_READ && num < instr->nread)
					iter += ril_instr_sn(buf+iter,max-iter, instr->read[num]);
				if (type == RIL_WRITE && num < instr->nwrite)
					iter += ril_instr_sn(buf+iter, max-iter, instr->write[num]);
			} else {
				if (instr->format[i+1]=='r') {
					for (int i = 0; i < instr->nread; i++) {
						iter += ril_instr_sn(buf+iter, max-iter, instr->read[i]);
						if ((i+1) < instr->nread)
							iter+=snprintf(buf+iter,max-iter,", ");
					}
				} else if (instr->format[i+1]=='w') {
					for (int i = 0; i < instr->nwrite; i++) {
						iter += ril_instr_sn(buf+iter, max-iter, instr->write[i]);
						if ((i+1) < instr->nwrite)
							iter+=snprintf(buf+iter,max-iter,", ");
					}
				}
			}
			i++;
			flast = i+1;
			continue;
		}

		if ((i+1)==flen)
			iter += snprintf(buf+iter, max-iter, "%s", instr->format+flast);
	}
	return iter;
}

ril_instruction *ril_instr_lift(ril_operation_table *table, r_disasm *dis)
{
	ril_instruction *instr = ril_instr_init(RIL_INSTR);
	ril_operation *op = ril_table_lookup(table, dis->mnemonic);
	if (!op) {
		writef("Err: no operation format for %s\r\n", dis->mnemonic);
		return instr;
	}

	for (int i = 0; i < dis->num_operands; i++) {
		int type = ril_dformat_parse(op->dformat, i);
		if (type == RIL_READ || type == RIL_RW) {
			ril_instr_add(instr,table->opr_decode(dis->op[i]), RIL_READ);
		}
		if (type == RIL_WRITE || type == RIL_RW) {
			ril_instr_add(instr,table->opr_decode(dis->op[i]), RIL_WRITE);
		}
	}
	instr->format = strdup(op->ilformat);
	instr->action = op->action;

	return instr;
}

int ril_dformat_parse(const char * dformat, int num_op)
{
	int last_type = 0;
	int len = strlen(dformat);
	for (int i = 0; i < len; i++) {
		char c = dformat[i];
		if (c == '$') {
			char nc = dformat[i+1];
			char nc2 = (i+2)<len?dformat[i+2]:0;
			if (nc == 'w') {
				last_type = RIL_WRITE;
				if (nc2=='r') last_type = RIL_RW, i++;
				i++;
				continue;
			} else if (nc == 'r') {
				last_type = RIL_READ;
				if (nc2=='w') last_type = RIL_RW, i++;
				i++;
				continue;
			} else if (nc >= 0x30 && nc <= 0x39) {
				int num = 0;
				int j = i;
				while (j < len && dformat[j] >=0x30&&dformat[j]<=0x39) {
					num *= 10;
					num += dformat[j] - 0x30;
				}
				if (num == num_op) return last_type;
			}
		} else if (c=='='||c==' '||c==',') continue;
	}
	return last_type;
}

/*Reverset IL Hash table*/
ril_operation_table *ril_table_init(int num_buckets, ril_operand_lift opr_decode)
{
	ril_operation_table *table = malloc(sizeof(ril_operation_table));

	table->buckets = calloc(num_buckets, sizeof(ril_operation*));
	table->num_buckets = num_buckets;
	table->opr_decode = opr_decode;

	return table;
}
void ril_table_destroy(ril_operation_table *table)
{
	if (!table) return;

	for (int i = 0; i < table->num_buckets; i++) {
		ril_operation *oper = table->buckets[i];
		ril_operation *next = NULL;
		while (oper) {
			next = oper->next;
			ril_oper_destroy(oper);
			oper = next;
		}
	}

	free(table->buckets);
	free(table);
}

void ril_table_insert(ril_operation_table *table, ril_operation *entry)
{
	long idx = entry->hash % table->num_buckets;
	ril_oper_add(&table->buckets[idx], entry);
}

void ril_table_remove(ril_operation_table *table, ril_operation *entry)
{
	long idx = entry->hash % table->num_buckets;
	ril_oper_add(&table->buckets[idx], entry);
}

ril_operation *ril_table_lookup(ril_operation_table *table, const char *name)
{
	long hash = hash_mnem(name);
	return ril_oper_find(table->buckets[hash%table->num_buckets], hash, name);
}

void ril_table_resize(ril_operation_table *table, int new_size)
{
	ril_operation **old = table->buckets;
	int old_size = table->num_buckets;

	table->num_buckets = new_size;
	table->buckets = calloc(new_size, sizeof(ril_operation*));

	for (int i = 0; i < old_size; i++) {
		ril_operation *head = old[i];
		while (head) {
			ril_table_insert(table, head);
			head = head->next;
		}
	}

	free(old);
}

unsigned long hash_mnem(const char *mnem)
{
	unsigned long hash = 5381;
	char c;
	while ((c=*mnem++))
		hash = ((hash << 5) + hash) + (unsigned char)c;

	return hash;
}

void ril_oper_add(ril_operation **head, ril_operation *e)
{
	if (!(*head)) {
		*head=e;
		return;
	}
	ril_operation *c=*head;
	while (c->next)
		c=c->next;
	c->next = e;
}

ril_operation *ril_oper_find(ril_operation *head, long hash, const char *name)
{
	while (head && (head->hash != hash || !!strcmp(head->name, name)))
		head=head->next;
	return head;
}

ril_operation *ril_oper_init(char *name, int action, char * dformat, char *ilformat)
{
	ril_operation *op = malloc(sizeof(ril_operation));

	op->hash = hash_mnem(name);
	op->next = NULL;

	op->name = name;
	op->ilformat = ilformat;
	op->dformat = dformat;
	op->action = action;

	return op;
}

void ril_oper_destroy(ril_operation *oper)
{
	if (!oper) return;

	free(oper);
}
