#include "ril.h"

ril_location *ril_loc_init()
{
	ril_location *loc = malloc(sizeof(ril_location));

	loc->size = 0;
	loc->type = RIL_NONE;
	loc->nest = 0;
	loc->next = NULL;
	loc->join_op = NULL;
	loc->iter = -1;

	return loc;
}

void ril_loc_destroy(ril_location *loc)
{
	if (!loc) return;
	if (loc->type == RIL_REG) {
		free(loc->reg);
	} else if (loc->type == RIL_MOFF) {
		ril_location *next = loc->next;
		ril_location *cur = loc->next;
		while (cur) {
			next = cur->next;
			ril_loc_destroy(cur);
			cur = next;
		}
	}
	if (loc->join_op)
		free(loc->join_op);
	free(loc);
}

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
		instr->operand = NULL;
	}
	instr->next = NULL;

	return instr;
}

void ril_instr_destroy(ril_instruction *instr)
{
	if (!instr) return;
	if (instr->type == RIL_OPER) {
		ril_loc_destroy(instr->operand);
		free(instr);
		return;
	}

	for (int i = 0; i < instr->nwrite; i++) {
		ril_instr_destroy(instr->write[i]);
	}

	for (int i = 0; i < instr->nread; i++) {
		ril_instr_destroy(instr->read[i]);
	}

	free(instr->write);
	free(instr->read);
	free(instr);
}

ril_location *ril_loc_dup(ril_location *loc)
{
	ril_location *dup = ril_loc_init();

	dup->size = loc->size;
	dup->type = loc->type;
	dup->iter = loc->iter;
	dup->nest = loc->nest;
	if (loc->join_op)
		dup->join_op = strdup(loc->join_op);
	if (loc->type == RIL_REG) {
		dup->reg = strdup(loc->reg);
	} else if (loc->type == RIL_MOFF) {
		ril_location *dupn = dup;
		ril_location *locn = loc->next;
		while (locn) {
			dupn->next = ril_loc_dup(locn);
			dupn = dupn->next;
			locn = locn->next;
		}
	} else if (loc->type == RIL_ADDR) {
		dup->addr = loc->addr;
	}
	return dup;
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
		dup->operand = ril_loc_dup(instr->operand);
	}
	dup->next = instr->next;
	return dup;
}
void ril_reduce(ril_instruction *instr)
{
	return;
	ril_instruction *cmp = NULL;
	int dist = 0;
	ril_instruction *cur = instr;
	while (cur) {
		//Check if cmp
		if (cmp) dist++;
		if (cur->action == RIL_COMPARE) {
			cmp = cur;
		}
		if (cmp && cur->action == RIL_CJUMP) {
			cur->nread += 2;
			cur->read = realloc(cur->read,sizeof(ril_instruction*)*cur->nread);
			cur->read[1] = cmp->read[0];
			cur->read[2] = cmp->read[1];
			dist = 0;
			cmp = NULL;
		}
		cur = cur->next;
	}
}

void ril_used_registers(struct text_buffer *text, ril_instruction *instr)
{
	char ** used = NULL;
	int num_used = 0;

	char ** args = NULL;
	int num_args = 0;
	while (instr) {
		for (int i = 0; i < instr->nwrite; i++) {
			if (instr->write[i]->type == RIL_REG) {
				int new = 1;
				char *reg = instr->write[i]->operand->reg;
				int r2 = x_register_index(reg);
				for (int j = 0; j < num_used; j++) {
					int r1=x_register_index(used[j]);
					if (X64_REG_BIN(r1) == X64_REG_BIN(r2)) {
						if (X64_REG_SIZE(r2) > X64_REG_BIN(r2))
							used[j] = reg;
						new = 0;
						break;
					}
				}
				if (new) {
					num_used++;
					if (!used)
						used=malloc(sizeof(char*));
					else
						used=realloc(used,sizeof(char*)*num_used);
					used[num_used-1] = reg;
				}
			}
		}

		for (int i = 0; i < instr->nread; i++) {
			if (instr->read[i]->type == RIL_REG) {
				int new = 1;
				char *reg = instr->read[i]->operand->reg;
				int r2 = x_register_index(reg);
				for (int j = 0; j < num_used; j++) {
					int r1 = x_register_index(used[j]);
					if (X64_REG_BIN(r1) == X64_REG_BIN(r2)) {
						new = 0;
						break;
					}
				}
				int new2 = 1;
				for (int j = 0; j < num_args; j++) {
					int r1 = x_register_index(args[j]);
					if (X64_REG_BIN(r1) == X64_REG_BIN(r2)) {
						new2 = 0;
						break;
					}
				}
				if (new2 && new) {
					num_args++;
					if (!args)
						args=malloc(sizeof(char*));
					else
						args=realloc(args,sizeof(char*)*num_args);
					args[num_args-1] = reg;
				}
			}
		}
		instr = instr->next;
	}
	int sc = text->cur_color;
	text->cur_color = 0;
	text_buffer_print(text, "%d Changed Regs:\r\n", num_used);
	for (int i = 0; i < num_used; i++)
		text_buffer_print(text, "%c%s", i==0?'\r':',', used[i]);
	text_buffer_print(text, "\r\n");
	text_buffer_print(text, "%d Registers read before write\r\n", num_args);
	for (int i = 0; i < num_args; i++)
		text_buffer_print(text, "%c%s", i==0?'\r':',', args[i]);
	text_buffer_print(text, "\r\n");
	text->cur_color = sc;

	free(used);
	free(args);
}

void ril_loc_print(struct text_buffer *text, ril_location *loc)
{
	if (!loc) return;
	if (loc->type == RIL_MOFF) {
		ril_location *ln = loc->next, *ln2 = NULL;
		char *nsym = NULL;
		if (ln && ln->next) {
			if (ln->join_op)
				nsym = ln->join_op;
			ln2 = ln->next;
			ln->next = NULL;
			ril_loc_print(text, ln);
			ln->next = ln2;
		} else ln2 = ln;

		text_buffer_print(text, "[%s", nsym ? nsym : "");
		ril_loc_print(text, ln2);
		char size = 'b';
		if (loc->size == 2)
			size = 'w';
		else if (loc->size==4)
			size = 'd';
		else if (loc->size ==8)
			size = 'q';
		text_buffer_print(text, "]");
		/*
		text_buffer_print(text, "m[");
		ril_loc_print(text, loc->next);
		text_buffer_print(text, "]");*/
	} else if (loc->type == RIL_REG) {
		text_buffer_print(text, "%s", loc->reg);
	} else if (loc->type == RIL_ADDR) {
		if (loc->addr > 0x128)
			text_buffer_print(text, "%#lx", loc->addr);
		else
			text_buffer_print(text, "%d", loc->addr);
	}
	if (!loc->nest && loc->next) {
		if (loc->join_op)
			text_buffer_print(text, "%s", loc->join_op);
		ril_loc_print(text, loc->next);
	}
	return;
	if (!loc) return;
	if (loc->type == RIL_MOFF) {
		writef("mem(");
		ril_loc_print(text, loc->next);
		writef(")");
	} else if (loc->type == RIL_REG) {
		writef("reg(%s)", loc->reg);
	} else if (loc->type == RIL_ADDR) {
		writef("imm(%#lx)", loc->addr);
	}
	if (!loc->nest && loc->next) {
		if (loc->join_op)
			writef("%s", loc->join_op);
		ril_loc_print(text, loc->next);
	}
}

int ril_loc_sn(char *buf, int max, ril_location *loc)
{
	if (!loc) return 0;
	int iter = 0;
	if (loc->type == RIL_MOFF) {
		ril_location *ln = loc->next, *ln2 = NULL;
		char *nsym = NULL;
		if (ln && ln->next) {
			if (ln->join_op)
				nsym = ln->join_op;
			ln2 = ln->next;
			ln->next = NULL;
			iter += ril_loc_sn(buf+iter, max-iter, ln);
			ln->next = ln2;
		} else ln2 = ln;

		iter += snprintf(buf+iter, max-iter, "[%s", nsym ? nsym : "");
		iter += ril_loc_sn(buf+iter, max-iter, ln2);
		char size = 'b';
		if (loc->size == 2)
			size = 'w';
		else if (loc->size==4)
			size = 'd';
		else if (loc->size ==8)
			size = 'q';
		iter += snprintf(buf+iter, max-iter, "]");
	} else if (loc->type == RIL_REG) {
		iter += snprintf(buf+iter, max-iter, "%s", loc->reg);
	} else if (loc->type == RIL_ADDR) {
		if (loc->addr > 0x128)
			iter += snprintf(buf+iter, max-iter, "%#lx", loc->addr);
		else
			iter += snprintf(buf+iter, max-iter, "%d", loc->addr);
	}
	if (!loc->nest && loc->next) {
		if (loc->join_op)
			iter += snprintf(buf+iter, max-iter, "%s", loc->join_op);
		iter += ril_loc_sn(buf+iter, max-iter, loc->next);
	}
	if (loc->iter >= 0) {
		iter += snprintf(buf+iter, max-iter, "_%d", loc->iter);
	}
	return iter;
}

void ril_instr_print(struct text_buffer *text, ril_instruction *instr)
{
	if (!instr) return;
	if (instr->type == RIL_OPER) {
		ril_loc_print(text, instr->operand);
		ril_instr_print(text, instr->next);
		return;
	}
	if (!instr->format) {
		ril_instr_print(text, instr->next);
		return;
	}
	int flen = strlen(instr->format);
	int flast = 0;
	for (int i = 0; i < flen; i++) {
		if (instr->format[i]=='$') {
			if (i-flast) {
				text_buffer_print(text, "%*.*s", i-flast, i-flast, instr->format+flast);
			}
			int type = instr->format[i+1]=='r'?RIL_READ:RIL_WRITE;
			int num = (i+2)<flen ? (signed int)instr->format[i+2]-0x30 : -1;
			if (num >=0 && num < 10) {
				i++;
				if (type == RIL_READ && num < instr->nread)
					ril_instr_print(text, instr->read[num]);
				if (type == RIL_WRITE && num < instr->nwrite)
					ril_instr_print(text, instr->write[num]);
			} else {
				if (instr->format[i+1]=='r') {
					for (int i = 0; i < instr->nread; i++) {
						ril_instr_print(text, instr->read[i]);
					}
				} else if (instr->format[i+1]=='w') {
					for (int i = 0; i < instr->nwrite; i++) {
						ril_instr_print(text, instr->write[i]);
					}
				}
			}
			i++;
			flast = i+1;
			continue;
		}

		if ((i+1)==flen)
			text_buffer_print(text, "%s", instr->format+flast);
	}
	text_buffer_print(text, "\r\n");
	if (instr->next)
		ril_instr_print(text, instr->next);

}

int ril_instr_sn(char *buf, int max, ril_instruction *instr)
{
	if (!instr) return 0;
	int iter = 0;
	if (instr->type == RIL_OPER) {
		iter += ril_loc_sn(buf, max, instr->operand);
		return iter;
	}
	if (!instr->format) {
		return iter;
	}
	if (instr->comment) {
		iter += snprintf(buf+iter, max-iter, "//");
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
			instr->nread++;
			if (!instr->read)
				instr->read = malloc(sizeof(ril_instruction));
			else
				instr->read=realloc(instr->read, sizeof(ril_instruction)*instr->nread);
			instr->read[instr->nread-1] = ril_instr_init(RIL_OPER);
			instr->read[instr->nread-1]->operand = table->opr_decode(dis->op[i]);
		}
		if (type == RIL_WRITE || type == RIL_RW) {
			instr->nwrite++;
			if (!instr->write)
				instr->write = malloc(sizeof(ril_instruction));
			else
				instr->write=realloc(instr->write, sizeof(ril_instruction)*instr->nwrite);
			instr->write[instr->nwrite-1] = ril_instr_init(RIL_OPER);
			instr->write[instr->nwrite-1]->operand = table->opr_decode(dis->op[i]);
		}
	}
	instr->format = op->ilformat;
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
