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

	return rev;
}

void reverset_destroy(reverset * rev)
{
	if (!rev) return;

	if (rev->file) r_file_destroy(rev->file);
	if (rev->disassembler) r_disassembler_destroy(rev->disassembler);
	if (rev->anal) r_analyzer_destroy(rev->anal);
	if (rev->pipe) r_pipe_destroy(rev->pipe);

	free(rev);
}

void reverset_openfile(reverset * rev, char * file)
{
	if (!rev->file) {
		rev->file = r_openfile(file);
	} else {
		r_file_destroy(rev->file);
		if (rev->disassembler) r_disassembler_destroy(rev->disassembler);
		if (rev->anal) r_analyzer_destroy(rev->anal);
		rev->disassembler = r_disassembler_init();
		rev->anal = r_analyzer_init();
		rev->file = r_openfile(file);
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

void reverset_execute(reverset * rev, char * cmd)
{
	int argc = 0;
	char ** args = reverset_split_line(cmd, &argc);
	reverset_eval(rev, argc, args);
}

void reverset_eval(reverset * rev, int argc, char ** argv)
{
	for (int i = 0; i < argc; i++) {
		char * arg = argv[i];
		int f_arg = i + 1;

		for (int j = 0; j < (sizeof(r_commands)/sizeof(r_cmd)); j++) {

			if (!strcmp(arg, r_commands[j].name)) {
				int used_args = r_commands[j].execute(rev, argv+f_arg, argc-i-1);
				i += used_args;
			}
		}
	}
}

void reverset_sh(reverset * rev)
{
	rev->status = rs_shell;

	char * input = NULL;
	char ** args = NULL;
	int argc = 0;

	do {
		printf(KNRM);
		printf("%#lx>", rev->address);
		input = reverset_readline();
		args = reverset_split_line(input, &argc);

		reverset_eval(rev, argc, args);

		if (rev->pipe->len > 0) {
			printf("%s\n", rev->pipe->buf);
			r_pipe_clear(rev->pipe);
		}

		free(input);
		for (int i = 0; i < argc; i++) {
			free(args[i]);
		}
		free(args);
	} while (rev->status == rs_shell);

}

char * reverset_readline()
{
	char buf[256];
	memset(buf, 0, 256);
	fgets(buf, 256, stdin);
	strtok(buf, "\n");

	return strdup(buf);
}

char ** reverset_split_line(char * line, int * num_args)
{
	char ** args = NULL;
	int argc = 0;

	int size = strlen(line);
	int iter = 0;

	char * carg = reverset_split(line);

	while (carg) {
		argc++;
		if (argc == 1) {
			args = malloc(sizeof(char*));
		} else {
			args = realloc(args, sizeof(char*) * argc);
		}
		args[argc-1] = carg;
		carg = reverset_split(NULL);
	}
	*num_args = argc;

	return args;
}

char * reverset_split(char * first)
{
	static char * str = NULL;
	if (first) str = first;

	if (str) {
		int len = strlen(str);
		int dquotes = 0;
		int quotes = 0;
		int offset = 0;
		int real_input = -1;
		for (int i = 0; i < (len+1); i++) {
			int new_str = 0;
			if (str[i] == '\'') {
				quotes = !quotes;
				if (!quotes) new_str = 1;
				else offset = i+1;
			} else if (str[i] == '\"') {
				dquotes = !dquotes;
				if (!dquotes) new_str = 1;
				else offset = i+1;
			} else if (!quotes && !dquotes && (str[i] == ' ' || str[i] == '\n' || str[i] == '\t')) {
				new_str = 1;
			} else if (i == len) {
				new_str = 1;
			} else {
				real_input = i;
			}

			if (new_str) {
				if ((i==0 && !str[i]) || real_input==-1) return NULL;
				str[i] = '\0';
				char * str2 = strdup(str+offset);
				str += i;
				if (i!=len) str++;

				return str2;		
			}
		}
	}

	return NULL;
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

int reverset_analyze(reverset * rev, char ** args, int num_args)
{
	r_meta_auto(rev->anal, rev->disassembler, rev->file);
	return 0;
}

int reverset_print(reverset * rev, char ** args, int num_args)
{
	char * arg = args[0];
	if (!arg) return 0;

	uint64_t addr = 0;

	if (!strcmp(arg, "all")) {
		rev->anal->function = 0;
	} else {
		rev->anal->function = 1;
		addr = reverset_resolve_arg(rev, arg);
		if (addr == -1) {
			r_pipe_write(rev->pipe, "No address found for \"%s\"\n", arg);
			return 1;
		}
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

	r_formatted_printall(rev->pipe, rev->disassembler, rev->anal, addr);

	return 1;
}

int reverset_disas(reverset * rev, char ** args, int num_arg)
{
	r_pipe_write(rev->pipe, "For automatic analysis use anal\n");
	
	if (!args) return 0;
	int all = 0;
	int segment = 0;
	int num_args = 0;
	char * tok = NULL;

	for (int i = 0; i < num_arg; i++) {
		if (!args[i]) continue;

		if (args[i][0] == '-') {
			num_args++;
			int n = strlen(args[i]);
			for (int j = 1; j < n; j++) {
				switch (args[i][j]) {
					case 'a':
						all = 1;
						break;
					case 'f':
						all = 0;
						break;
				}
			}
		} else if (!tok) tok = args[i];
		else break;
	}
	if (!tok) return num_args;

	uint64_t addr = reverset_resolve_arg(rev, tok);
	if (addr == -1) {
		r_pipe_write(rev->pipe, "No address found for \"%s\"\n", tok);
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

int reverset_asm(reverset * rev, char ** args, int num_args)
{
	char * arg = args[0];
	if (!arg) return 0;

	if (!assemblers[rev->file->arch]) {
		r_pipe_write(rev->pipe, "Assembling is only currently available for 64 bit programs\n");
		return 1;
	}
	//Assemble 
	int num_bytes = 0;
	unsigned char * bytes = assemblers[rev->file->arch](arg, rev->address, &num_bytes);
	char buf[256];
	int iter = 0;

	if (bytes) {
		iter += snprintf(buf+iter, 256-iter, "%d bytes: ", num_bytes);
		for (int i = 0; i < num_bytes; i++) {
			iter += snprintf(buf+iter, 256-iter, "%02x ", bytes[i]);
		}
		iter += snprintf(buf+iter, 256-iter, "\n");
	}
	r_pipe_write(rev->pipe, "%s\n", buf);

	return 1;
}

int reverset_write(reverset * rev, char ** args, int num_args)
{
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

int reverset_goto(reverset * rev, char ** args, int num_args)
{
	char * arg = args[0];
	if (!arg) return 0;

	uint64_t addr = reverset_resolve_arg(rev, arg);
	if (addr == -1) {
		r_pipe_write(rev->pipe, "No address found for \"%s\"\n", arg);
		return 1;
	}
	rev->address = addr;

	return 1;
}

int reverset_strmod(reverset * rev, char ** args, int num_arg)
{
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

int reverset_quit(reverset * rev, char ** args, int num_args)
{
	rev->status = rs_none;
	return 0;
}

int reverset_list(reverset * rev, char ** args, int num_args)
{
	char * arg = args[0];
	if (!arg) return 0;

	int symbols = -1;
	if (!strcmp(arg, "symbols") || !strcmp(arg, "symbol")) {
		for (int i = 0; i < rev->file->num_symbols; i++) {
			rsymbol sym = rev->file->symbols[i];
			if (!symbols && sym.type == R_FUNC) {
				r_pipe_write(rev->pipe, "symbol: %s address: %#lx\n", sym.name, sym.addr64);
			} else if (symbols) {
				r_pipe_write(rev->pipe, "symbol: %s address: %#lx\n", sym.name, sym.addr64);
			}
		}
	}
	else if (!strcmp(arg, "functions") || !strcmp(arg, "function")) {
		for (int i = 0; i < rev->anal->num_functions; i++) {
			r_function func = rev->anal->functions[i];
			r_pipe_write(rev->pipe, "function: %s address: %#lx\n", func.name, func.start);
		}
	} else if (!strcmp(arg, "string") || !strcmp(arg, "strings")) {
		for (int i = 0; i < rev->file->num_strings; i++) {
			rstring str = rev->file->strings[i];
			r_pipe_write(rev->pipe,  "section: %s address: %#lx str: \"%s\"\n", rev->file->sections[str.section].name, str.addr64, str.string);
		}
	}

	return 1;
}