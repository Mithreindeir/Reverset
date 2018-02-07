#include "rformat.h"

void r_formatted_printjump(r_pipe * pipe, r_analyzer * anal, uint64_t addr, uint64_t sb, uint64_t eb)
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
	r_pipe_write(pipe, "%s" , buf);
}

void r_formatted_print(r_pipe * pipe, r_disasm * disas, r_analyzer * anal,  uint64_t start, uint64_t end)
{
	r_pipe_write(pipe, KBLU);
	//Print all xrefs except those that where the xref froms location is within the bounds
	for (int i = 0; i < disas->metadata->num_xrefto; i++) {
		uint64_t addr = disas->metadata->xref_to[i].addr;
		if (addr > start && addr <= end) continue;
		r_pipe_write(pipe, ";\tXREF TO HERE FROM %#lx\n", addr);
	}
	for (int i = 0; i < disas->metadata->num_xreffrom; i++) {
		//r_pipe_write(pipe, "XREF TO FROM HERE TO %lx\n", disas->metadata->xref_from[i]);
	}
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
		if (anal->function && disas->metadata->type == r_tret) break;
	}

	for (int i = 0; i < disassembler->num_instructions; i++) {
		r_disasm * disas = disassembler->instructions[i];
		if (disas->address < addr) continue;

		r_formatted_print(pipe, disas, anal, addr, end);
		if (anal->function && disas->metadata->type == r_tret) break;
	}
}