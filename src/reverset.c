#include "reverset.h"

reverset * reverset_init()
{
	reverset * rev = malloc(sizeof(reverset));

	rev->address = 0;
	rev->file = NULL;
	rev->disassembler = r_disassembler_init();
	rev->anal = r_analyzer_init();
	rev->status = rs_none;
	//rev->pipe = NULL;

	return rev;
}

void reverset_destroy(reverset * rev)
{
	if (!rev) return;

	if (rev->file) r_file_destroy(rev->file);
	if (rev->disassembler) r_disassembler_destroy(rev->disassembler);
	if (rev->anal) r_analyzer_destroy(rev->anal);

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
	if (disassemblers[rev->file->arch] != NULL) {
		rev->disassembler->disassemble =  disassemblers[rev->file->arch];
		rev->address = rev->file->entry_point; 
	} else {
		printf("Architecture not supported\n");
		return;
	}
}

char * reverset_execute(reverset * rev, char * cmd)
{
	int argc = 0;
	char ** args = reverset_split_line(cmd, &argc);
	return reverset_eval(rev, argc, args);
}

char * reverset_eval(reverset * rev, int argc, char ** argv)
{
	for (int i = 0; i < argc; i++) {
		char * arg = argv[i];
		int f_arg = i + 1;

		for (int j = 0; j < (sizeof(r_commands)/sizeof(r_cmd)); j++) {

			if (!strcmp(arg, r_commands[j].name)) {
				i++;
				int largs = argc - i;
				if (largs < r_commands[j].argc) {
					return strdup(r_commands[j].usage);
				} else {
					return r_commands[j].execute(rev, argv+f_arg);
					i += r_commands[j].argc-1;
				}

			}
		}
	}
	return NULL;
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

		char * output = reverset_eval(rev, argc, args);

		if (output) {
			printf("%s\n", output);			
		}

		free(input);
		for (int i = 0; i < argc; i++) {
			free(args[i]);
		}
		free(args);
		if (output) free(output);
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
	for (int i = 0; i < rev->file->num_symbols; i++) {
		rsymbol sym = rev->file->symbols[i];
		if (sym.type == R_FUNC && !strcmp(sym.name, arg)) {
			addr = sym.addr64;
			found = 1;
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
	if (!found) addr = rev->address;
	return addr;
}

char* reverset_analyze(reverset * rev, char ** args)
{

}

char* reverset_print(reverset * rev, char ** args)
{
	char * arg = args[0];
	if (!arg) return NULL;

	uint64_t addr = 0;

	if (!strcmp(arg, "all")) {
		rev->anal->function = 0;
	} else {
		rev->anal->function = 1;
		addr = reverset_resolve_arg(rev, arg);
	}
	
	char * print = r_meta_printall(rev->disassembler, rev->anal, addr);
	return print;
}

char* reverset_disas(reverset * rev, char ** args)
{
	char * arg = args[0];
	if (!arg) return NULL;

	uint64_t addr = reverset_resolve_arg(rev, arg);
	rev->disassembler->overwrite = 1;
	r_disassembler_pushaddr(rev->disassembler, addr);
	r_disassemble(rev->disassembler, rev->file);
	r_meta_analyze(rev->anal, rev->disassembler, rev->file);

	return NULL;
}

char * reverset_asm(reverset * rev, char ** args)
{
	char * arg = args[0];
	if (!arg) return NULL;

	if (!assemblers[rev->file->arch]) {
		return strdup("Assembling is only currently available for 64 bit programs\n");
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
	return strdup(buf);
}

char* reverset_write(reverset * rev, char ** args)
{
	char * arg = args[0];
	if (!arg) return NULL;

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
			return strdup("invalid bytes\n");
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

	return NULL;
}

char* reverset_goto(reverset * rev, char ** args)
{
	char * arg = args[0];
	if (!arg) return NULL;

	uint64_t addr = reverset_resolve_arg(rev, arg);
	rev->address = addr;

	return NULL;
}

char * reverset_quit(reverset * rev, char ** args)
{
	rev->status = rs_none;
	return NULL;
}

char * reverset_list(reverset * rev, char ** args)
{
	char * arg = args[0];
	if (!arg) return NULL;
	int symbols = 0;
	if (!strcmp(arg, "symbols") || !strcmp(arg, "symbol")) symbols = 1;
	else if (!strcmp(arg, "functions") || !strcmp(arg, "function"))
		symbols = 0;
	else return NULL;

	int cnum = 0;
	int onum = 0;
	char * printed = NULL;

	for (int i = 0; i < rev->file->num_symbols; i++) {
		rsymbol sym = rev->file->symbols[i];
		char buf[256];
		int iter = 0;

		if (!symbols && sym.type == R_FUNC) {
			iter += snprintf(buf+iter, 256-iter, "symbol: %s address: %#lx\n", sym.name, sym.addr64);
		} else if (symbols) {
			iter += snprintf(buf+iter, 256-iter, "symbol: %s address: %#lx\n", sym.name, sym.addr64);
		}
		if (iter > 0) {
			cnum += iter;
			if (onum == 0) {
				printed = malloc(cnum);
			} else {
				printed = realloc(printed, cnum);
			}
			memcpy(printed+onum, buf, iter);
			onum = cnum;
		}
	}
	if (printed) printed[cnum] = 0;
	
	return printed;
}