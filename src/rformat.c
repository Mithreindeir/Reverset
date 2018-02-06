#include "rformat.h"

char * r_formatted_printjump(r_analyzer * anal, uint64_t addr, uint64_t sb, uint64_t eb)
{
	int j_addr = 0;
	int start = 0;
	int dir = 0;

	int p = 0;
	char buf[7];
	buf[6] = 0;
	memset(buf, 0x20, 6);

	for (int i = 0; i < anal->num_branches; i++) {
		if (anal->branches[i].start < sb || anal->branches[i].end > eb) continue;

		if (anal->branches[i].start == addr) {
			j_addr = 1;
			start = 0;
			dir = anal->branches[i].dir;
			p = anal->branches[i].nested;
		}
		if (anal->branches[i].end == addr) {
			j_addr = 1;
			start = 1;
			dir = anal->branches[i].dir;
			p = anal->branches[i].nested;
		}
		if ((anal->branches[i].start <= addr) && (anal->branches[i].end >= addr)) {
			int op = p;
			p = anal->branches[i].nested;
			if (p >= 5) buf[0] = '|';
			else buf[5-(p+1)] = '|';
			p = p > op ? p : op;
		}
	}

	int total_lines = ((j_addr) ? 2+p : 0);
	int iter = 6 - total_lines;
	while (iter < 0) {
		p--;
		total_lines = ((j_addr) ? 2+p : 0);
		iter = 6 - total_lines;
	}
	if (j_addr) {
		if (start) {
			buf[iter++] = '`';
			for (int i = 0; i < p; i++) {
				if (dir) buf[iter++] = '=';
				else buf[iter++] = '-';
			}
			if (dir) buf[iter++] = '<';
			else buf[iter++] = '>';
		} else {
			buf[iter++] = ',';
			for (int i = 0; i < p; i++) {
				if (dir) buf[iter++] = '-';
				else buf[iter++] = '=';
			}
			if (dir) buf[iter++] = '>';
			else buf[iter++] = '<';			
		}
	}

	buf[6] = 0;
	//printf("%s ", buf);
	return strdup(buf);
}

char * r_formatted_print(r_disasm * disas, r_analyzer * anal, int * idx, uint64_t start, uint64_t end)
{
	char * buf = malloc(256);
	memset(buf, 0, 256);
	int iter = 0;

	iter += snprintf(buf+iter, 256-iter, KBLU);
	if (disas->metadata->label) iter += snprintf(buf+iter, 256-iter, "//\t%s\n", disas->metadata->label);
	iter += snprintf(buf+iter, 256-iter, KRED);
	iter += snprintf(buf+iter, 256-iter, "%#x:   ", disas->address);
	iter += snprintf(buf+iter, 256-iter, KCYN);
	int b = 8*3;
	for (int i = 0; i < disas->used_bytes; i++) {
		if ((b-3) <= 0) {
			iter += snprintf(buf+iter, 256-iter, ".");
			break;
		} 
		iter += snprintf(buf+iter, 256-iter, "%02x ", disas->raw_bytes[i]);
		b -= 3;
	}
	while (b > 0) {
		iter += snprintf(buf+iter, 256-iter, "   ");
		b -= 3;
	}
	iter += snprintf(buf+iter, 256-iter, "\t");
	iter += snprintf(buf+iter, 256-iter, KRED);
	
	char * jmp = r_formatted_printjump(anal, disas->address, start, end);
	iter += snprintf(buf+iter, 256-iter, "%s ", jmp);
	free(jmp);
	int space = 6-strlen(disas->mnemonic);
	iter += snprintf(buf+iter, 256-iter, KBLU);
	iter += snprintf(buf+iter, 256-iter, "%s ", disas->mnemonic);
	for (int i = 0; i < space; i++) iter += snprintf(buf+iter, 256-iter, " ");
	if (disas->metadata && (disas->metadata->type == r_tcall || disas->metadata->type == r_tujump || disas->metadata->type == r_tcjump))
		iter += snprintf(buf+iter, 256-iter, KYEL);
	else
		iter += snprintf(buf+iter, 256-iter, KRED);
	for (int i = 0; i < disas->num_operands; i++) {
		if (i!=0) iter += snprintf(buf+iter, 256-iter, ",");
		iter += snprintf(buf+iter, 256-iter, "%s", disas->op[i]);
	}
	if (disas->metadata->comment) iter += snprintf(buf+iter, 256-iter, "\t # %s", disas->metadata->comment);
	iter += snprintf(buf+iter, 256-iter, "\n");
	buf[iter] = 0;
	*idx = iter;
	if (iter > 0) {
		buf = realloc(buf, iter);
		return buf;
	}
	free(buf);
	return NULL;
}

char * r_formatted_printall(r_disassembler * disassembler, r_analyzer * anal, uint64_t addr)
{
	uint64_t end = 0;
	for (int i = 0; i < disassembler->num_instructions; i++) {
		r_disasm * disas = disassembler->instructions[i];
		if (disas->address < addr) continue;
		end = disas->address + disas->used_bytes;
		if (disas->metadata->type == r_tret) break;
	}

	char * printed = NULL;
	int num_char = 0;
	int old_char = 0;
	for (int i = 0; i < disassembler->num_instructions; i++) {
		r_disasm * disas = disassembler->instructions[i];
		if (disas->address < addr) continue;

		int iter = 0;
		char * instr = r_formatted_print(disas, anal, &iter, addr, end);

		num_char += iter;
		if (num_char > old_char) {
			if (!printed) {
				printed = malloc(num_char);
			} else {
				printed = realloc(printed, num_char);
			}
			memcpy(printed+old_char, instr, iter);
		}
		old_char = num_char;
		if (instr) free(instr);
		if (anal->function && disas->metadata->type == r_tret) break;
	}
	if (num_char > 0) printed[num_char-1] = 0;

	return printed;
}