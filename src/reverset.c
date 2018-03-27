#include "reverset.h"

reverset * reverset_init()
{
	reverset * rev = malloc(sizeof(reverset));

	rev->address = 0;
	rev->file = NULL;
	rev->disassembler = r_disassembler_init();
	rev->anal = r_analyzer_init();
	rev->status = rs_none;
	rev->pipe = r_pipe_init(1024);

	rev->shell = dshell_init();
	dshell_loadconf(rev->shell, "color.example");
	dshell_addfunc(rev->shell, "anal", &reverset_analyze, rev);
	dshell_addfunc(rev->shell, "print", &reverset_print, rev);
	dshell_addfunc(rev->shell, "goto", &reverset_goto, rev);
	dshell_addfunc(rev->shell, "quit", &reverset_quit, rev);
	dshell_addfunc(rev->shell, "list", &reverset_list, rev);
	dshell_addfunc(rev->shell, "asm", &reverset_asm, rev);
	dshell_addfunc(rev->shell, "disas", &reverset_disas, rev);
	dshell_addfunc(rev->shell, "graph", &reverset_graph, rev);
	//rev->shell->buffer->cur_color = 37;

	return rev;
}

void reverset_destroy(reverset * rev)
{
	if (!rev) return;

	if (rev->file) r_file_destroy(rev->file);
	if (rev->disassembler) r_disassembler_destroy(rev->disassembler);
	if (rev->anal) r_analyzer_destroy(rev->anal);
	if (rev->pipe) r_pipe_destroy(rev->pipe);
	if (rev->shell) dshell_destroy(rev->shell);

	free(rev);
}

void reverset_openfile(reverset * rev, char * file, char * perm)
{
	if (!rev->file) {
		rev->file = r_openfile(file, perm);
	} else {
		r_file_destroy(rev->file);
		if (rev->disassembler) r_disassembler_destroy(rev->disassembler);
		if (rev->anal) r_analyzer_destroy(rev->anal);
		rev->disassembler = r_disassembler_init();
		rev->anal = r_analyzer_init();
		rev->file = r_openfile(file, perm);
	}
	//At least find strings
	r_file_find_strings(rev->file);
	if (disassemblers[rev->file->arch] != NULL) {
		rev->disassembler->disassemble =  disassemblers[rev->file->arch];
		rev->address = rev->file->entry_point;
	} else {
		printf("Architecture not supported\n");
		return;
	}
}

void reverset_sh(reverset * rev)
{
	rev->status = rs_shell;
	char buf[32];
	memset(buf, 0, 32);
	char *prompt = &buf[0];
	rev->shell->conf->prompt = &prompt;
	char *str = NULL;
	do {
		snprintf(prompt, 32, "[%#lx]->", rev->address);
		get_cursor(&rev->shell->tmpx, &rev->shell->tmpy);
		str = dshell_update(rev->shell);
		dshell_render(rev->shell);
	} while(rev->status == rs_shell);
}

uint64_t reverset_resolve_arg(reverset * rev, char * arg)
{
	uint64_t addr = 0;
	int found = 0;
	for (int i = 0; i < rev->anal->num_functions; i++) {
		r_function func = rev->anal->functions[i];
		if (!strcmp(func.name, arg)) {
			found = 1;
			addr = func.start;
			break;
		}
	}
	for (int i = 0; i < rev->file->num_symbols; i++) {
		rsymbol sym = rev->file->symbols[i];
		if (!sym.name) continue;
		if (found) break;
		if (sym.type == R_FUNC && !strcmp(sym.name, arg)) {
			addr = sym.addr64;
			found = 1;
			break;
		}
	}
	if (!found) {
		int len = 0;
		if (r_meta_isaddr(arg, &len)) {
			int base = 16 * (!!strncmp(arg, "0x", 2));
			addr = (uint64_t)strtol(arg, NULL, base);
			found = 1;
		}
	}
	if (!found && !strncmp(arg, "here", 4)) {
		addr = rev->address;
		found = 1;
	}
	else if (!found) return -1;
	return addr;
}

int reverset_hex(reverset * rev, char ** args, int num_arg)
{
	if (num_arg == 0) return 0;
	if (!args) return 0;

	int num_args = 0;
	char * tok = NULL;

	for (int i = 0; i < num_arg; i++) {
		if (!args[i]) continue;

		if (args[i][0] == '-') {
			num_args++;
			int n = strlen(args[i]);
			for (int j = 1; j < n; j++) {
				switch (args[i][j]) {
					case 'n':
						break;
					case 'f':
						break;
				}
			}
		} else if (!tok) tok = args[i];
		else break;
	}
	if (!tok) return num_args;
	num_args++;

	int num = strtol(tok, NULL, 0);
	uint64_t paddr = r_file_get_paddr(rev->file, rev->address);

	for (int i = paddr; i < (paddr+num) && i < rev->file->size; i++) {
		r_pipe_write(rev->pipe, "%02x ", rev->file->raw_file[i]);
		if ((i % 32)==0 && i > 1)r_pipe_write(rev->pipe, "\n");
	}

	return num_args;
}

int reverset_analyze(struct text_buffer*buf,int argc, char**argv, void*data)
{
	reverset *rev = data;
	r_meta_auto(rev->anal, rev->disassembler, rev->file);
	return 0;
}

int reverset_print(struct text_buffer*buf, int argc,char ** args,void*data)
{
	reverset *rev = data;
	if (argc < 2) return 0;
	char * arg = args[1];
	if (!arg) return 0;
	int num = 0;
	for (int i = 1; i < argc; i++) {
		if (args[i][0]=='-') {
			if (args[i][1]=='n')
				num = 1;
		}
	}

	uint64_t addr = rev->address;
	int max = -1;

	if (!strcmp(arg, "all")) {
		rev->anal->function = 0;
	} else if (!num) {
		rev->anal->function = 1;
		addr = reverset_resolve_arg(rev, arg);
		if (addr == -1) {
			text_buffer_print(buf, "No address found for \"%s\"\r\n", arg);
			return 1;
		}
	} else {
		if (argc < 3) {
			text_buffer_print(buf, "No number specified \r\n");
			return 1;
		}
		max = strtol(args[2], NULL, 10);
	}

	int found = 0;
	for (int i = 0; i < rev->disassembler->num_instructions; i++ ) {
		r_disasm * disas = rev->disassembler->instructions[i];
		if (disas->address == addr) {
			found = 1;
			break;
		} else if (disas->address > addr ) break;
	}

	if (0 && !found) {
		rev->disassembler->recursive = 1;
		rev->disassembler->overwrite = 0;
		r_disassembler_pushaddr(rev->disassembler, addr);
		r_disassemble(rev->disassembler, rev->file);
		r_meta_analyze(rev->anal, rev->disassembler, rev->file);
	}
	r_formatted_printall(buf, rev->disassembler, rev->anal, addr, max);

	return 1;
}

int reverset_graph(struct text_buffer*buf, int argc, char **argv, void*data)
{
	reverset *rev = data;
	if (argc < 2) return 0;
	char * arg = argv[1];
	uint64_t addr = rev->address;
	addr = reverset_resolve_arg(rev, arg);
	if (addr==-1) {
		text_buffer_print(buf, "No address found for \"%s\"\r\n", arg);
		return 1;
	}
	clear_scrn();
	set_cursor(1, 1);
	for (int i = 0; i < rev->anal->num_functions; i++) {
		r_function func = rev->anal->functions[i];
		if (func.start==addr && func.nbbs) {
			rbb_graph(func.bbs, func.nbbs);
			for (int i = 0; i < func.nbbs; i++) {
				func.bbs[i]->drawn = 0;
				//r_formatted_rect(buf,rev->disassembler,rev->anal,func.bbs[i]);
			}
			r_formatted_rect(buf,rev->disassembler,rev->anal,func.bbs[0]);
			r_formatted_graph(buf,rev->disassembler,rev->anal,func.bbs[0]);
			break;
		}
	}
	return 1;
}

int reverset_disas(struct text_buffer *buf, int argc, char **argv, void*data)
{
	reverset * rev = data;
	if (argc < 2) return 0;

	int oc = buf->cur_color;
	buf->cur_color = 37;
	text_buffer_print(buf, "For most files you will want to use anal\r\n");
	buf->cur_color = oc;

	if (!argv) return 0;
	int all = 0;
	int segment = 0;
	int num_args = 0;
	char * tok = NULL;

	for (int i = 1; i <argc; i++) {
		if (!argv[i]) continue;

		if (argv[i][0] == '-') {
			num_args++;
			int n = strlen(argv[i]);
			for (int j = 1; j < n; j++) {
				switch (argv[i][j]) {
					case 'a':
						all = 1;
						break;
					case 'f':
						all = 0;
						break;
				}
			}
		} else if (!tok) tok = argv[i];
		else break;
	}
	if (!tok) return num_args;

	uint64_t addr = reverset_resolve_arg(rev, tok);
	if (addr == -1) {
		text_buffer_print(buf, "No address found for \"%s\"\r\n", tok);
		return 1;
	}
	int r = rev->disassembler->recursive;
	rev->disassembler->recursive = all;
	rev->disassembler->overwrite = 0;
	r_disassembler_pushaddr(rev->disassembler, addr);
	r_disassemble(rev->disassembler, rev->file);
	r_meta_analyze(rev->anal, rev->disassembler, rev->file);
	rev->disassembler->recursive = r;

	return 1;
}

int reverset_asm(struct text_buffer*tbuf,int argc, char**argv, void*data)
{
	reverset *rev = data;
	if (argc < 2) return 0;

	char * arg = argv[1];
	if (!arg) return 0;

	if (!assemblers[rev->file->arch]) {
		text_buffer_print(tbuf, "No assembler found\r\n");
		return 1;
	}
	//Assemble
	int num_bytes = 0;
	unsigned char * bytes = assemblers[rev->file->arch](arg, rev->address, &num_bytes);
	char buf[256];
	memset(buf, 0, 255);
	int iter = 0;

	if (bytes) {
		//iter += snprintf(buf+iter, 256-iter, "%d bytes: ", num_bytes);
		for (int i = 0; i < num_bytes; i++) {
			iter += snprintf(buf+iter, 256-iter, "%02x ", bytes[i]);
		}
		iter += snprintf(buf+iter, 256-iter, "\r\n");
	}
	text_buffer_print(tbuf, "%s -> %s\n", arg, buf);
	free(bytes);

	return 1;
}

int reverset_write(reverset * rev, char ** args, int num_args)
{
	if (num_args == 0) return 0;

	char * arg = args[0];
	if (!arg) return 0;

	int size = strlen(arg);
	unsigned char byte_buf[256];
	int num_bytes = 0;
	int write = 1;
	memset(byte_buf, 0, 256);
	int i = 0;
	for (; i < (size-1); i+=2) {
		if (arg[i]==' ') {
			i--;
			continue;
		}
		unsigned char a = arg[i];
		a = (a >= 0x30 && a < 0x40) ? a - 0x30 : ((a <= 'f' && a >= 'a') ? (a -'a'+10) : ((a <= 'F' && a >= 'A' ? (a-'A'+10) : 0)));
		unsigned char b = 0;
		if ((i+1) < size) {
			b = arg[i+1];
		} else {
			write = 0;
			r_pipe_write(rev->pipe, "invalid bytes\n");
			return 1;
		}
		b = (b >= 0x30 && b < 0x40) ? b - 0x30 : ((b <= 'f' && b >= 'a') ? (b -'a'+10) : ((b <= 'F' && b >= 'A' ? (b -'A'+10) : 0)));
		unsigned char f = (a<<4) + (b&0x0f);
		byte_buf[num_bytes++] = f;
	}

	if (write) {
		r_file_patch(rev->file, rev->address, byte_buf, num_bytes);
		rev->disassembler->overwrite = 1;
		r_disassembler_pushaddr(rev->disassembler, rev->address);
		r_disassemble(rev->disassembler, rev->file);
		r_meta_analyze(rev->anal, rev->disassembler, rev->file);
	}

	return 1;
}

int reverset_goto(struct text_buffer*buf,int argc, char **argv, void *data)
{
	reverset *rev = data;
	if (argc < 2) return 0;
	char * arg = argv[1];
	if (!arg) return 0;

	uint64_t addr = reverset_resolve_arg(rev, arg);
	if (addr == -1) {
		text_buffer_print(buf, "No address found for \"%s\"\n", arg);
		return 1;
	}
	rev->address = addr;

	return 1;
}

int reverset_strmod(reverset * rev, char ** args, int num_arg)
{
	if (num_arg == 0) return 0;

	int num_args = 0;
	int reverse = 0;
	int u_num = 0;
	int num = -1;
	char * tok = NULL;
	for (int i = 0; i < num_arg; i++) {
		if (!args[i]) continue;

		if (args[i][0] == '-') {
			num_args++;
			int n = strlen(args[i]);
			for (int j = 1; j < n; j++) {
				switch (args[i][j]) {
					case 'r':
						reverse = 1;
						break;
					case 'n':
						u_num = 1;
						break;
				}
			}
		} else if (!tok) tok = args[i];
		else break;
	}
	if (!tok) return num_args;
	num_args++;

	if (u_num) num = strtol(tok, NULL, 0);

	int str_len = strlen(tok);
	int len = rev->pipe->len;
	char * out = r_pipe_read(rev->pipe, 0, len);
	int line_num = 0;
	for (int i = 0; i < len; ) {
		if (u_num) {
			if (out[i]=='\n') line_num++;
			if (num != -1 && line_num >= num){
				len = i-1;
				out[i] = 0;
				break;
			}
			i++;
			continue;
		}
		int substring = 0;
		int c = i;
		while (out[c] != '\n' && out[c]) {
			if (!substring && !strncmp(out+c, tok, str_len)) substring = 1;
			c++;
		}
		if (!reverse && !substring) {
			memset(out+i, 0, c-i + 1);
		} else if (substring && reverse) {
			memset(out+i, 0, c-i + 1);
		}
		line_num++;
		i=c+1;

	}
	r_pipe_clear(rev->pipe);

	for (int i = 0; i < len; i++) {
		if (!out[i]) continue;
		int old_len = rev->pipe->len;
		r_pipe_write(rev->pipe, "%s", out+i);
		int diff = rev->pipe->len - old_len;
		i += diff;
	}
	free(out);

	return num_args;
}

int reverset_quit(struct text_buffer*buf, int argc, char **argv, void *data)
{
	reverset *rev = data;
	text_buffer_print(buf, "Goodbye!\r\n");
	rev->status = rs_none;
	return 0;
}

int reverset_list(struct text_buffer *buf, int argc, char**argv, void*data)
{
	reverset *rev = data;
	if (argc < 2) return 0;

	char * arg = argv[1];
	if (!arg) return 0;

	int symbols = -1;
	int oc = buf->cur_color;
	buf->cur_color = 37;
	if (!strcmp(arg, "symbols") || !strcmp(arg, "symbol")) {
		for (int i = 0; i < rev->file->num_symbols; i++) {
			rsymbol sym = rev->file->symbols[i];
			if (!symbols && sym.type == R_FUNC) {
				text_buffer_print(buf, "symbol: %s address: %#lx\r\n", sym.name, sym.addr64);
			} else if (symbols) {
				text_buffer_print(buf, "symbol: %s address: %#lx\r\n", sym.name, sym.addr64);
			}
		}
	}
	else if (!strcmp(arg, "functions") || !strcmp(arg, "function")) {
		for (int i = 0; i < rev->anal->num_functions; i++) {
			r_function func = rev->anal->functions[i];
			text_buffer_print(buf, "function: %s addr: %#lx end: %#lx size: %d\r\n", func.name, func.start, func.start + func.size, func.size);
		}
	} else if (!strcmp(arg, "string") || !strcmp(arg, "strings")) {
		for (int i = 0; i < rev->file->num_strings; i++) {
			rstring str = rev->file->strings[i];
			text_buffer_print(buf,  "section: %s address: %#lx str: \"%s\"\r\n", rev->file->sections[str.section].name, str.addr64, str.string);
		}
	}
	buf->cur_color = oc;
	return 1;
}
