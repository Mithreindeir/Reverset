#include "ril.h"

ril_location *ril_loc_init()
{
	ril_location *loc = malloc(sizeof(ril_location));

	loc->size = 0;
	loc->type = RIL_NONE;
	loc->nest = 0;
	loc->next = NULL;
	loc->join_op = NULL;

	return loc;
}

void ril_loc_destroy(ril_location *loc)
{
	if (!loc) return;

	free(loc);
}

ril_instruction *ril_instr_init()
{
	ril_instruction *instr = malloc(sizeof(ril_instruction));

	instr->mnem=NULL, instr->format = NULL;
	instr->write=NULL, instr->read=NULL;
	instr->nwrite=0, instr->nread=0;
	instr->next = NULL;

	return instr;
}

void ril_instr_destroy(ril_instruction *instr)
{
	if (!instr) return;

	free(instr->mnem);
	for (int i = 0; i < instr->nwrite; i++)
		free(instr->write[i]);

	for (int i = 0; i < instr->nread; i++)
		free(instr->read[i]);

	free(instr->write);
	free(instr->read);
	free(instr);
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

void ril_instr_print(struct text_buffer *text, ril_instruction *instr)
{
	if (!instr) return;
	/*writef("OPERATION: %s\r\n", instr->mnem);
	writef("WRITE:\r\n");
	for (int i = 0; i < instr->nwrite; i++) {
		ril_loc_print(instr->write[i]);
	}
	writef("\r\nREAD:\r\n");
	for (int i = 0; i < instr->nread; i++) {
		ril_loc_print(instr->read[i]);
	}*/
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
					ril_loc_print(text, instr->read[num]);
				if (type == RIL_WRITE && num < instr->nwrite)
					ril_loc_print(text, instr->write[num]);
			} else {
				if (instr->format[i+1]=='r') {
					for (int i = 0; i < instr->nread; i++) {
						ril_loc_print(text, instr->read[i]);
					}
				} else if (instr->format[i+1]=='w') {
					for (int i = 0; i < instr->nwrite; i++) {
						ril_loc_print(text, instr->write[i]);
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

ril_instruction *ril_instr_lift(ril_operation_table *table, r_disasm *dis)
{
	ril_instruction *instr = ril_instr_init();
	ril_operation *op = ril_table_lookup(table, dis->mnemonic);
	if (!op) {
		writef("Err: no operation format for %s\r\n", dis->mnemonic);
		return instr;
	}

	for (int i = 0; i < dis->num_operands; i++) {
		int type = ril_dformat_parse(op->dformat, i);
		if (type == RIL_READ) {
			instr->nread++;
			if (!instr->read)
				instr->read = malloc(sizeof(ril_location));
			else
				instr->read=realloc(instr->read, sizeof(ril_location)*instr->nread);
			instr->read[instr->nread-1] = table->opr_decode(dis->op[i]);
		} else if (type == RIL_WRITE) {
			instr->nwrite++;
			if (!instr->write)
				instr->write = malloc(sizeof(ril_location));
			else
				instr->write=realloc(instr->write, sizeof(ril_location)*instr->nwrite);
			instr->write[instr->nwrite-1] = table->opr_decode(dis->op[i]);
		}
	}
	instr->format = op->ilformat;

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
			if (nc == 'w') {
				last_type = RIL_WRITE;
				i++;
				continue;
			} else if (nc == 'r') {
				last_type = RIL_READ;
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
		ril_oper_destroy(table->buckets[i]);
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

ril_operation *ril_oper_init(char *name, char * dformat, char *ilformat)
{
	ril_operation *op = malloc(sizeof(ril_operation));

	op->hash = hash_mnem(name);
	op->next = NULL;

	op->name = name;
	op->ilformat = ilformat;
	op->dformat = dformat;

	return op;
}

void ril_oper_destroy(ril_operation *oper)
{
	if (!oper) return;

	free(oper);
}
