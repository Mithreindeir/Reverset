#include "rformat.h"

void r_formatted_graph(struct text_buffer *textb, r_disassembler *disassembler, r_analyzer *anal, rbb *bb)
{
	bb->drawn = 1;
	for (int i = 0; i < bb->num_next; i++) {
		if (!bb->next[i]->drawn) {
			r_formatted_rect(textb, disassembler,anal,bb->next[i]);
		}
	}
	for (int i = 0; i < bb->num_next; i++) {
		if (!bb->next[i]->drawn)
			r_formatted_graph(textb,disassembler,anal,bb->next[i]);
	}
}

void r_formatted_rect(struct text_buffer *textb, r_disassembler *disassembler, r_analyzer *anal, rbb *bb)
{
	r_disasm *disas = NULL;
	char buf[256];
	int max_x = 0, max_y = 0;
	max_x = snprintf(buf, 255, "%#lx:", bb->start);
	char ** lines = malloc(sizeof(char*));
	lines[0] = strdup(buf);
	int num_lines = 1, iter = 0;
	for (int i = 0; i < disassembler->num_instructions; i++) {
		disas = disassembler->instructions[i];
		if (disas->address < bb->start || (disas->address+disas->used_bytes) > bb->end)
			continue;
		memset(buf, 0, 255);
		iter = 0;
		int space = 6-strlen(disas->mnemonic);
		iter+=snprintf(buf+iter,255-iter, "%s ", disas->mnemonic);
		for (int i = 0; i < space; i++) iter+=snprintf(buf+iter,255-iter, " ");
		for (int i = 0; i < disas->num_operands; i++) {
			if (i!=0) iter+=snprintf(buf+iter,255-iter, ", ");
			iter+=snprintf(buf+iter, 255-iter, "%s", disas->op[i]);
		}
		max_x = iter > max_x ? iter : max_x;
		num_lines++;
		lines=realloc(lines,sizeof(char*)*num_lines);
		lines[num_lines-1] = strdup(buf);
	}
	max_x++;
	int sx=0, sy=0;
	get_cursor(&sx, &sy);
	int fy = sy;
	int oc = textb->cur_color;
	textb->cur_color = 37;
	text_buffer_print(textb, CURSOR_POS, sy, sx);
	for (int i = 0; i <= max_x; i++) {
		char c = '-';
		c = i==0 ? ',' : (i==max_x ? '.':c);
		text_buffer_print(textb, "%c", c);
	}
	text_buffer_print(textb, "\r\n");
	sy++;
	for (int i = 0; i < num_lines; i++) {
		text_buffer_print(textb, CURSOR_POS, sy, sx);
		int diff=max_x-strlen(lines[i]);
		text_buffer_print(textb, "|");
		textb->cur_color = 0;
		text_buffer_print(textb, "%s", lines[i]);
		textb->cur_color = 37;
		while(--diff>0)
			text_buffer_print(textb, " ");
		text_buffer_print(textb, "|\r\n");
		free(lines[i]);
		sy++;
	}
	text_buffer_print(textb, CURSOR_POS, sy, sx);
	for (int i = 0; i <= max_x; i++) {
		char c = '-';
		c = i==0 ? '`' : (i==max_x ? '\'':c);
		text_buffer_print(textb, "%c", c);
	}
	sy++;
	text_buffer_print(textb, "\r\n");
	set_cursor(sx,sy);
	free(lines);
	textb->cur_color = oc;
}

void r_formatted_printjump(struct text_buffer*textb, r_analyzer * anal, uint64_t addr, uint64_t sb, uint64_t eb)
{
	int j_addr = 0;
	int start = 0;
	int dir = 0;
	int buf_size = 6;

	int startp = buf_size;
	int endp = buf_size;

	int p = 0;
	char buf[7];//buf_size + 1
	buf[buf_size] = 0;
	memset(buf, 0x20, buf_size);

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

			char fill = '|';
			if (anal->branches[i].start == addr) {
				fill = ',';
			} else if (anal->branches[i].end == addr){
				fill = '`';
			}

			int op = p;
			p = anal->branches[i].nested;
			int idx = 0;
			if (p >= (buf_size-1)) {
				idx = 0;
			} else {
				idx = (buf_size-1)-(p+1);
			}
			buf[idx] = fill;
			idx++;
			if (fill == '`')  startp = idx < startp ? idx : startp;
			else if (fill == ',') endp = idx < endp ? idx : endp;

			p = p > op ? p : op;
		}
	}

	int total_lines = ((j_addr) ? 2+p : 0);
	int iter = buf_size - total_lines;
	while (iter < 0) {
		p--;
		total_lines = ((j_addr) ? 2+p : 0);
		iter = buf_size - total_lines;
	}

	if (j_addr) {
		if (start) {
			for (int i = startp; i < buf_size; i++) {
				if (dir) buf[i] = '=';
				else buf[i] = '-';
			}
			if (dir) buf[buf_size-1] = '<';
			else buf[buf_size-1] = '>';
		} else {
			for (int i = endp; i < buf_size; i++) {
				if (dir) buf[i] = '-';
				else buf[i] = '=';
			}
			if (dir) buf[buf_size-1] = '>';
			else buf[buf_size-1] = '<';
		}
	}
	buf[buf_size] = 0;
	text_buffer_print(textb, "%s", buf);
}

void r_formatted_print(struct text_buffer *textb, r_disasm * disas, r_analyzer * anal,  uint64_t start, uint64_t end)
{
	//Print all xrefs except those that where the xref froms location is within the bounds
	for (int i = 0; i < disas->metadata->num_xrefto; i++) {
		uint64_t addr = disas->metadata->xref_to[i].addr;
		//if (addr > start && addr <= end) continue;
		text_buffer_print(textb, ";\tXREF TO HERE FROM %#lx\r\n", addr);
	}
	for (int i = 0; i < disas->metadata->num_xreffrom; i++) {
		//text_buffer_print(textb, "XREF TO FROM HERE TO %lx\n", disas->metadata->xref_from[i]);
	}
	if (disas->metadata->label) text_buffer_print(textb, "//\t%s\r\n", disas->metadata->label);
	text_buffer_print(textb, "%#x:   ", disas->address);
	int b = 8*3;
	for (int i = 0; i < disas->used_bytes; i++) {
		if ((b-3) <= 0) {
			text_buffer_print(textb, ".");
			break;
		}
		text_buffer_print(textb, "%02x ", disas->raw_bytes[i]);
		b -= 3;
	}
	while (b > 0) {
		text_buffer_print(textb, "   ");
		b -= 3;
	}
	text_buffer_print(textb, "\t");
	r_formatted_printjump(textb, anal, disas->address, start, end);

	int space = 6-strlen(disas->mnemonic);
	text_buffer_print(textb, "%s ", disas->mnemonic);
	for (int i = 0; i < space; i++) text_buffer_print(textb, " ");
	for (int i = 0; i < disas->num_operands; i++) {
		if (i!=0) text_buffer_print(textb, ", ");
		text_buffer_print(textb, "%s", disas->op[i]);
	}
	if (disas->metadata->comment) text_buffer_print(textb, "\t # %s", disas->metadata->comment);
	text_buffer_print(textb, "\r\n");
}

void r_formatted_printall(struct text_buffer *textb, r_disassembler * disassembler, r_analyzer * anal, uint64_t addr, int max)
{
	uint64_t end = 0;
	int start = -1;
	for (int i = 0; i < disassembler->num_instructions; i++) {
		r_disasm * disas = disassembler->instructions[i];
		if (disas->address < addr) continue;
		if (start==-1) start = i;
		end = disas->address + disas->used_bytes;
		if (anal->function && disas->metadata->type == r_tret) break;
	}
	max = max==-1 ? disassembler->num_instructions : start + max;
	if (start == -1) return;

	for (int i = start; i < max; i++) {
		r_disasm * disas = disassembler->instructions[i];
		r_formatted_print(textb, disas, anal, addr, end);
		if (anal->function && disas->metadata->type == r_tret) break;
	}
}
