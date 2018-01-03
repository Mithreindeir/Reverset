#include "formatter.h"


formatter * formatter_init(x86_instruction ** instructions, int num_instructions)
{
	formatter * format = malloc(sizeof(formatter));
	format->num_jumps = 0;
	format->jumps = NULL;

	x86_instruction * ci;
	int addr = 0;
	if (num_instructions > 0 ) addr = instructions[0]->address;

	for (int i = 0; i < num_instructions; i++) {
		ci = instructions[i];

		if (ci->mnemonic[0] == 'j') {
			struct jump j;
			j.start = ci->address;
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
	format->comments = NULL;
	format->num_comments = 0;
	format->functions = NULL;
	format->num_functions = 0;

	return format;
}

void formatter_addcomment(formatter * format, struct comment c)
{
	for (int i = 0; i < format->num_comments; i++) {
		if (c.origin_addr == format->comments[i].origin_addr && c.addr == format->comments[i].addr) return;
	}
	format->num_comments++;
	if (format->num_comments == 1) {
		format->comments = malloc(sizeof(struct comment));
	} else {
		format->comments = realloc(format->comments, sizeof(struct comment) * format->num_comments);
	}
	format->comments[format->num_comments-1] = c;	
}

void formatter_analyze(formatter * format, int start_addr, x86_instruction ** instructions, int num_instructions, elf_file * file)
{
	int addr = start_addr;
	x86_instruction * ci;
	int num_functions = 0;

	elf_section_data * rodata = elf_get_section(file, ".rodata");
	elf_section_data * data = elf_get_section(file, ".data");
	elf_section_data * bss = elf_get_section(file, ".bss");

	char buf[256];
	int iter = 0;
	struct comment c;

	for (int i = 0; i < num_instructions; i++) {
		ci = instructions[i];
		addr = ci->address;
		int instr_addr = 0;
		if (ci->op1.type == IMM32) instr_addr = ci->op1.imm32;
		if (ci->op2.type == IMM32) instr_addr = ci->op2.imm32;

		if (ci->op1.type == REL1632) instr_addr = ci->op1.rel1632;
		if (ci->op2.type == REL1632) instr_addr = ci->op2.rel1632;
		memset(buf, 0, 256);
		iter = 0;
		if (instr_addr != 0) {
			//printf("%#x is in %s\n", instr_addr, elf_find_section(file, instr_addr));
			//getchar();
		}

		if (rodata && IN_SECTION(instr_addr, rodata)) {
			int off = instr_addr - rodata->addr;
			char buf2[256];
			memset(buf2, 0, 256);
			formatter_strcpy(buf2, rodata->data+off, 256);
			iter += snprintf(buf, 256, "str: \"%s\"", buf2);
			c.origin_addr = ci->address;
			c.addr =  addr;
			c.type = 0;
			c.comment = strdup(buf);
		} else if (0 && data && IN_SECTION(instr_addr, data)) {
			int off = instr_addr - data->addr;
			iter += snprintf(buf, 256, "str.%s", data->data+off);
			c.addr =  addr;
			c.type = 0;
			c.comment = strdup(buf);
		} else if (0 && bss && IN_SECTION(instr_addr, bss)) {
			int off = instr_addr - bss->addr;
			iter += snprintf(buf, 256, "str.%s", bss->data+off);
			c.addr = addr;
			c.type = 0;
			c.comment = strdup(buf);
		}
		if (iter != 0) formatter_addcomment(format, c);

		for (int j = 0; j < file->num_syms; j++) {
			elf_sym sym = file->syms[j];
			if (strlen(sym.name) < 2) continue;
			for (int i = 0; i < strlen(sym.name); i++) {
				if (sym.name[i]=='\n') sym.name[i] = 0x20;
			}
			if (sym.addr == addr && (strlen(sym.name) > 0)) {
				memset(buf, 0, 256);
				iter = 0;
				c.addr = addr;
				c.origin_addr = addr;

				if (sym.type == STT_FUNC) c.type = c_function_start;
				else c.type = c_none;

				iter += snprintf(buf+iter, 256-iter, "sym.%s", sym.name);
				c.comment = strdup(buf);
				formatter_addcomment(format, c);
			}
			if (ci->op1.type == REL1632 && ci->op1.rel1632 == sym.addr) {
				memset(buf, 0, 256);
				iter = 0;
				c.addr = ci->op1.rel1632;
				c.origin_addr = addr;

				if (sym.type == STT_FUNC) c.type = c_function_call;
				else c.type = c_none;

				iter += snprintf(buf+iter, 256-iter, "<sym.%s>", sym.name);
				c.comment = strdup(buf);
				formatter_addcomment(format, c);
			}

			if (ci->op2.type == REL1632 && ci->op2.rel1632 == sym.addr) {
				memset(buf, 0, 256);
				iter = 0;
				c.addr = ci->op2.rel1632;
				c.origin_addr = addr;

				if (sym.type == STT_FUNC) c.type = c_function_call;
				else c.type = c_none;

				iter += snprintf(buf+iter, 256-iter, "<sym.%s>", sym.name);
				c.comment = strdup(buf);
				formatter_addcomment(format, c);
			}

			if (ci->op1.imm32 != 0 && ci->op1.type == IMM32 && ci->op1.imm32 == sym.addr) {
				memset(buf, 0, 256);
				iter = 0;
				c.addr = ci->op1.imm32;
				c.origin_addr = addr;

				if (sym.type == STT_FUNC) c.type = c_function_call;
				else c.type = c_none;

				iter += snprintf(buf+iter, 256-iter, "<sym.%s>", sym.name);
				c.comment = strdup(buf);
				formatter_addcomment(format, c);
			}
			if (ci->op2.imm32 != 0 && ci->op2.type == IMM32 && ci->op2.imm32 == sym.addr) {
				memset(buf, 0, 256);
				iter = 0;
				c.addr = ci->op2.imm32;
				c.origin_addr = addr;

				if (sym.type == STT_FUNC) c.type = c_function_call;
				else c.type = c_none;

				iter += snprintf(buf+iter, 256-iter, "<sym.%s>", sym.name);
				c.comment = strdup(buf);
				formatter_addcomment(format, c);
			}
		}
		addr += ci->used_bytes;
	}
	
	for (int i = 0; i < num_instructions; i++) {
		ci = instructions[i];
		for (int j = 0; j < format->num_comments; j++) {
			if (format->comments[j].type == c_function_call && format->comments[j].addr == ci->address) {
				memset(buf, 0, 256);
				iter = 0;
				c.type = c_code_xref;
				c.origin_addr = ci->address;
				c.addr = format->comments[j].origin_addr;

				iter += snprintf(buf+iter, 256-iter, "CODE XREF FROM %#x", format->comments[j].origin_addr);
				c.comment = strdup(buf);
				formatter_addcomment(format, c);
			}
		}
	}

	format->functions = malloc(sizeof(function) * num_functions);
	format->num_functions++;
}

struct comment * formatter_getcomment(formatter * format, int addr)
{
	for (int i = 0; i < format->num_comments; i++) {
		if (format->comments[i].origin_addr == addr) {
			return &format->comments[i];
		}
	}
	return NULL;
}

void formatter_printjump(formatter * format, int addr)
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
	printf("%s ", buf);

}

void formatter_precomment(formatter * format, int addr)
{
	for (int i = 0; i < format->num_comments; i++) {
		if (format->comments[i].origin_addr == addr) {
			comment_type t = format->comments[i].type;
			if (t == c_data_xref || t == c_code_xref || t == c_function_start)	
				printf("//\t%s\n", format->comments[i].comment);
		}
	}
}

void formatter_postcomment(formatter * format, int addr)
{
	int comment = 0;
	for (int i = 0; i < format->num_comments; i++) {
		if (format->comments[i].origin_addr == addr) {
			comment_type t = format->comments[i].type;
			if (!(t == c_data_xref || t == c_code_xref || t == c_function_start)) {
				if (!comment) 	printf(" ");
				comment = 1;
				printf("%s", format->comments[i].comment);
			}
		}
	}
}

void formatter_printcomment(formatter * format, int addr)
{
	int comment = 0;
	for (int i = 0; i < format->num_comments; i++) {
		if (format->comments[i].origin_addr == addr) {
			if (!comment) 	printf(" ");
			comment = 1;
			printf("%s ", format->comments[i].comment);
		}
	}
}

void formatter_destroy(formatter * format)
{
	if (!format) return;
	if (format->jumps) free(format->jumps);
	free(format);
}

//Strcpy that removes spaces and newline characters
void formatter_strcpy(char * dst, char * src, int max_len)
{
	int l = strlen(src);
	int len = l > max_len ? max_len : l;

	int c=0;
	for (int i = 0; i < len; i++) {
		if (src[i] == 0) break;
		if (src[i] == '\n') continue;
		if (src[i] == ' ') {
			dst[c++] = '_';
			continue;
		}
		dst[c++] = src[i];
	}
}