#include "formatter.h"


formatter * formatter_init(int start_addr, x86_instruction ** instructions, int num_instructions)
{
	formatter * format = malloc(sizeof(formatter));
	format->num_jumps = 0;
	format->jumps = NULL;

	int addr = start_addr;
	x86_instruction * ci;
	for (int i = 0; i < num_instructions; i++) {
		ci = instructions[i];

		if (ci->mnemonic[0] == 'j') {
			struct jump j;
			j.start = addr;
			j.end = ci->op1.rel1632;
			j.direction = 0;
			j.nested = 0;
			if (j.start > j.end) {
				j.direction = 1;
				int tmp = j.end;
				j.end = j.start;
				j.start = tmp;
			}
			format->num_jumps++;
			if (format->num_jumps == 1) {
				format->jumps = malloc(sizeof(struct jump));
			} else {
				format->jumps = realloc(format->jumps, sizeof(struct jump) * format->num_jumps);
			}
			format->jumps[format->num_jumps-1] = j;
		}
		addr += ci->used_bytes;
	}

	for (int i = 0; i < format->num_jumps; i++) {
		struct jump j1 = format->jumps[i];	
		//3 Cases
		//Jump completely enclosed in other jump
		//Jumps start inside of other jump
		//Jumps end inside of other jump
		int jcase = 0;
		for (int k = 0; k < format->num_jumps; k++) {
			if (k==i) continue;
			struct jump j2 = format->jumps[k];
			jcase = 0;
			if ((j2.start > j1.start) && (j2.end < j1.end)) jcase = 1;
			else if ((j2.start > j1.start) && (j2.start < j1.end)) jcase = 2;
			else if ((j2.end > j1.start) && (j2.end < j1.end)) jcase = 3;
			
			switch (jcase) {
				case 1:
					format->jumps[i].nested++;
					break;
				case 2:
					format->jumps[i].nested++;
					break;
				case 3:
					//format->jumps[k].nested++;
					break;
				default: break;
			}
		}
	}
	return format;
}

/*
->1
->2
<-2
<-1
//2 has nest of 0 1 has nest of 1

->1
->2
<-1
->2

//1 has nest of 1 and 2 has nest of 0

*/


void formatter_printline(formatter * format, int addr)
{
	int j_addr = 0;	
	int start = 0;
	int within_bounds = 0;
	int dir = 0;

	int p = 0;
	char buf[7];
	buf[6] = 0;
	memset(buf, 0x20, 6);

	for (int i = 0; i < format->num_jumps; i++) {
		if (format->jumps[i].start == addr) {
			j_addr = 1;
			start = 0;
			dir = format->jumps[i].direction;
			p = format->jumps[i].nested;
		}
		if (format->jumps[i].end == addr) {
			j_addr = 1;
			start = 1;
			dir = format->jumps[i].direction;
			p = format->jumps[i].nested;
		}
		if ((format->jumps[i].start <= addr) && (format->jumps[i].end >= addr)) {
			int op = p;
			p = format->jumps[i].nested;
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
			buf[iter++] = '\\';
			for (int i = 0; i < p; i++) {
				buf[iter++] = '-';
			}
			if (dir) buf[iter++] = '<';
			else buf[iter++] = '>';
		} else {
			buf[iter++] = '/';
			for (int i = 0; i < p; i++) {
				buf[iter++] = '-';
			}
			if (dir) buf[iter++] = '>';
			else buf[iter++] = '<';
		}
	}
	buf[6] = 0;
	printf("%s ", buf);

}

void formatter_destroy(formatter * format)
{
	if (!format) return;
	if (format->jumps) free(format->jumps);
	free(format);
}