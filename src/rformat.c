#include "rformat.h"

void r_formatted_printjump(r_pipe * pipe, r_analyzer * anal, uint64_t addr, uint64_t sb, uint64_t eb)
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
	r_pipe_write(pipe, "%s" , buf);
}

void r_formatted_print(r_pipe * pipe, r_disasm * disas, r_analyzer * anal,  uint64_t start, uint64_t end)
{
	r_pipe_write(pipe, KBLU);
	if (disas->metadata->label) r_pipe_write(pipe, "//\t%s\n", disas->metadata->label);
	r_pipe_write(pipe, KRED);
	r_pipe_write(pipe, "%#x:   ", disas->address);
	r_pipe_write(pipe, KCYN);
	int b = 8*3;
	for (int i = 0; i < disas->used_bytes; i++) {
		if ((b-3) <= 0) {
			r_pipe_write(pipe, ".");
			break;
		} 
		r_pipe_write(pipe, "%02x ", disas->raw_bytes[i]);
		b -= 3;
	}
	while (b > 0) {
		r_pipe_write(pipe, "   ");
		b -= 3;
	}
	r_pipe_write(pipe, "\t");
	r_pipe_write(pipe, KRED);
	
	r_formatted_printjump(pipe, anal, disas->address, start, end);

	int space = 6-strlen(disas->mnemonic);
	r_pipe_write(pipe, KBLU);
	r_pipe_write(pipe, "%s ", disas->mnemonic);
	for (int i = 0; i < space; i++) r_pipe_write(pipe, " ");
	if (disas->metadata && (disas->metadata->type == r_tcall || disas->metadata->type == r_tujump || disas->metadata->type == r_tcjump))
		r_pipe_write(pipe, KYEL);
	else
		r_pipe_write(pipe, KRED);
	for (int i = 0; i < disas->num_operands; i++) {
		if (i!=0) r_pipe_write(pipe, ", ");
		//Check if it is a string or symbol 
		if (disas->op[i][0]=='\"') r_pipe_write(pipe, KYEL);

		r_pipe_write(pipe, "%s", disas->op[i]);
	}
	r_pipe_write(pipe, KGRN);
	if (disas->metadata->comment) r_pipe_write(pipe, "\t # %s", disas->metadata->comment);
	r_pipe_write(pipe, "\n");

}

void r_formatted_printall(r_pipe * pipe, r_disassembler * disassembler, r_analyzer * anal, uint64_t addr)
{
	uint64_t end = 0;
	for (int i = 0; i < disassembler->num_instructions; i++) {
		r_disasm * disas = disassembler->instructions[i];
		if (disas->address < addr) continue;
		end = disas->address + disas->used_bytes;
		if (disas->metadata->type == r_tret) break;
	}

	for (int i = 0; i < disassembler->num_instructions; i++) {
		r_disasm * disas = disassembler->instructions[i];
		if (disas->address < addr) continue;

		r_formatted_print(pipe, disas, anal, addr, end);
		if (anal->function && disas->metadata->type == r_tret) break;
	}
}