#include "ranal.h"

void r_meta_auto(r_analyzer * anal, r_disassembler * disassembler, r_file * file)
{
	/*Automatic analysis:
	Start at entry point and all function symbols. Recursively every address found in the disassembly is jumped to and disassembled, and stops at rets. A bound is created between the call and ret.
	Name these as function
	*/
	disassembler->recursive = 1;
	disassembler->overwrite = 1;
	disassembler->linear = 0;

	for (int i = 0; i < file->num_symbols; i++) {
		if (file->symbols[i].type != R_FUNC) continue;

		r_disassembler_pushaddr(disassembler, file->symbols[i].addr64);
	}
	r_disassembler_pushaddr(disassembler, file->entry_point);
	r_disassemble(disassembler, file);
	/*Recursively disassemble all calls*/

	/*Analyze after all disassembling is done, but don't call analyzers that replace operands  */
	if (file->arch == r_x86_64)
		r_meta_rip_resolve(disassembler, file);

	r_meta_calculate_branches(anal, disassembler);
	r_meta_reloc_resolve(disassembler, file);
	r_meta_find_xrefs(disassembler, file);

	/*TODO add other ways to identify main when using a runtime other than libc
	Attempt to identify main by checking for "__libc_start_main" symbol, and finding the function that has an xref right above libc
		...
		mov rdi, 0x40356c <- this is main
		call __libc_start_main
	*/
	uint64_t call_to_libc = 0;
	uint64_t adjacent_libc = 0;
	for (int i = 0; i < file->num_symbols; i++) {
		if (!file->symbols[i].name) continue;
		if (!strcmp(file->symbols[i].name, "__libc_start_main")) {
			call_to_libc = file->symbols[i].addr64;
		}
	}
	if (call_to_libc) {
		for (int i = 0; i < disassembler->num_instructions; i++) {
			r_disasm * disas = disassembler->instructions[i];
			if (disas->address == call_to_libc) {
				if (disas->metadata->num_xrefto > 0) adjacent_libc = disas->metadata->xref_to[0].addr;
				break;
			}
		}
	}
	if (adjacent_libc) {
		for (int i = 0; i < disassembler->num_instructions; i++) {
			r_disasm * disas = disassembler->instructions[i];
			if (disas->address == adjacent_libc && i > 0) {
				adjacent_libc = disassembler->instructions[i-1]->address;
				break;
			}
		}
	}


	/*Mark as function if they have xrefs to the start */
	for (int i = 0; i < disassembler->num_bounds; i++) {
		block_bounds b = disassembler->bounds[i];
		if ((b.end-b.start)<1) continue;

		/*Find disassembly with address*/
		int found = 0;
		r_disasm * disas = NULL;
		for (int j = 0; j < disassembler->num_instructions; j++) {
			disas = disassembler->instructions[j];
			if (disas->address == b.start) {
				found = 1;
				break;
			}
		}
		if (!found) continue;

		/*Check if there are xrefs to it*/
		int call = 0;
		int main = 0;
		for (int i = 0; i < disas->metadata->num_xrefto; i++) {
			if (disas->metadata->xref_to[i].addr == adjacent_libc) {
				main = 1;
				break;
			}

			if (disas->metadata->xref_to[i].type == r_tcall) {
				call = 1;
				break;
			}
		}
		if (!call && !main) continue;

		/*Check if there is a symbol with the bound start address*/
		char * name = NULL;

		for (int j = 0; j < file->num_symbols; j++) {
			if (!file->symbols[j].name) continue;
			rsymbol sym = file->symbols[j];
			if (sym.addr64 == b.start) {
				int len = snprintf(NULL, 0, "sym.%s", sym.name);
				name = malloc(len+1);
				snprintf(name, len+1, "sym.%s", sym.name);
				break;
			}
		}
		if (!name && main) {
			name = strdup("func.main");
		} else if (!name) {
			int len = snprintf(NULL, 0, "func.%x", b.start);
			name = malloc(len+1);
			snprintf(name, len+1, "func.%x", b.start);
		}


		anal->num_functions++;
		if (anal->num_functions == 1) {
			anal->functions = malloc(sizeof(r_function));
		} else {
			anal->functions = realloc(anal->functions, sizeof(r_function) * anal->num_functions);
		}
		r_function func;
		func.name = name;
		func.start = b.start;
		func.size = b.end - b.start;
		func.argc = 0;
		func.args = NULL;
		anal->functions[anal->num_functions-1] = func;
		r_function_arguments(disassembler, anal, &anal->functions[anal->num_functions-1], file->abi);
	}

	/*Lastly call replace functions with func first*/
	r_meta_func_replace(disassembler, file, anal);
	r_meta_symbol_replace(disassembler, file);
	r_meta_string_replace(disassembler, file);
}

void r_meta_func_replace(r_disassembler * disassembler, r_file * file, r_analyzer * anal)
{
	if (file->abi != rc_sysv64 && file->abi != rc_sysv32) return;
	char buf[256];
	memset(buf, 0, 256);
	//Add labels for code that is the address of a file symbol
	//And Find references to symbols and replace address with symbol name
	for (int j = 0; j < disassembler->num_instructions; j++) {
		r_disasm * disas = disassembler->instructions[j];
		for (int i = 0; i < anal->num_functions; i++) {
			r_function func = anal->functions[i];
			if (!func.name) continue;
			int idx = 0;
			if ((idx=r_meta_find_addr(disas->metadata, func.start, META_ADDR_BOTH) != 0 && !disas->metadata->comment)) {
				idx--;
				int ridx = 0;
				for (int k = 0; k < disas->num_operands; k++) {
					int len = 0;
					if (r_meta_isaddr(disas->op[k], &len)) {
						if (idx==ridx) {
							ridx = k;
							break;
						}
						ridx++;
					}
				}
				if (disas->op[ridx]) {
					disas->metadata->comment = disas->op[ridx];
					disas->op[ridx] = NULL;
					//free(disas->op[0]);
				}
				//Go back and look for arguments
				if (disas->metadata->type == r_tcall) {
					r_function_arg_replacer(disassembler, j, &anal->functions[i], file->abi);
				} else {
					disas->op[ridx] = strdup(func.name);
				}
			}
			if (!disas->metadata->label && disas->address == func.start) {
				int iter = 0;
				iter += snprintf(buf+iter, 256-iter, "%s(", func.name);
				for (int k = 0; k < func.argc; k++) {
					if (k!=0) iter += snprintf(buf+iter, 256-iter, ", ");
					iter += snprintf(buf+iter, 256-iter, "%s", func.args[k]);
				}
				iter += snprintf(buf+iter, 256-iter, ")");
				disas->metadata->label = strdup(buf);
			}
		}
	}
}

void r_meta_analyze(r_analyzer * anal, r_disassembler * disassembler, r_file * file)
{
	if (file->arch == r_x86_64)
		r_meta_rip_resolve(disassembler, file);

	r_meta_calculate_branches(anal, disassembler);
	r_meta_reloc_resolve(disassembler, file);
	r_meta_find_xrefs(disassembler, file);

	r_meta_func_replace(disassembler,file, anal);
	r_meta_symbol_replace(disassembler, file);
	r_meta_string_replace(disassembler, file);
}

void r_meta_calculate_branches(r_analyzer * anal, r_disassembler * disassembler)
{
	//Upon reanalysis assume instruction have changed so remove all branches
	if (anal->branches) free(anal->branches);
	anal->num_branches = 0;

	for (int j = 0; j < disassembler->num_instructions; j++) {
		r_disasm * disas = disassembler->instructions[j];
		if (disas->metadata->type == r_tcjump || disas->metadata->type == r_tujump) {
			//Check this branch doesnt already exist
			int found = -1;
			for (int i = 0; i < anal->num_branches; i++) {
				if (anal->branches[i].start == disas->address) {
					found = i;
					break;
				}
			}

			r_branch branch;
			branch.start = disas->address;
			branch.end = 0;
			branch.indirect = 0;
			branch.nested = 0;
			branch.conditional = disas->metadata->type == r_tujump;

			int status = 0;
			for (int i = 0; i < disas->num_operands; i++) {				
				branch.end = r_meta_get_address(disas->op[i], &status);

				if (status == 2) branch.indirect = 1;
				else if (!status) continue;
				break;
			}

			if (branch.end > branch.start) {
				branch.dir = 0;
			} else {
				branch.dir = 1;
				uint64_t tmp = branch.end;
				branch.end = branch.start;
				branch.start = tmp;
			}
			if (status != 0 && found == -1) {
				anal->num_branches++;
				if (anal->num_branches == 1) {
					anal->branches = malloc(sizeof(r_branch));
				} else {
					anal->branches = realloc(anal->branches, sizeof(r_branch) * anal->num_branches);
				}
				anal->branches[anal->num_branches-1] = branch;
			} else if (status != 0 && found < anal->num_branches) {
				anal->branches[found] = branch;
			}
		}
	}


	/*Initial guess at nesting (TODO fix if nest overlaps 5 jumps with nest of 1 then jmp should be at nest of 2 not 5
	Fix might be starting at jumps with a nest of 0 and working up, not allowing the nest of any jump to be greater than 1+the nest of the highest jmp that is overlapped.
	*/
	for (int i = 0; i < anal->num_branches; i++) {
		r_branch b = anal->branches[i];

		for (int j = 0; j < anal->num_branches; j++) {
			if (j==i) continue;
			r_branch b2 = anal->branches[j];

			if ((b2.start >= b.start) && (b2.end <= b.end)) anal->branches[i].nested++;
			else if ((b2.start >= b.start) && (b2.start <= b.end)) anal->branches[i].nested++;
		}
	}
}

void r_meta_rip_resolve(r_disassembler * disassembler, r_file * file)
{
	char buf[256];
	memset(buf, 0, 256);
	//Add comments for RIP relative addresses (x64 only)
	for (int j = 0; j < disassembler->num_instructions; j++) {
		r_disasm * disas = disassembler->instructions[j];
		for (int k = 0; k < disas->num_operands; k++) {
			int n = r_meta_rip_relative(disas->op[k]);
			if (n != 0) {
				memset(buf, 0, 20);
				snprintf(buf, 20, "%#x", n + disas->address+disas->used_bytes);
				disas->metadata->comment = strdup(buf);
				break;
			}
		} 
	}
}

void r_meta_reloc_resolve(r_disassembler * disassembler, r_file * file)
{

	//Find reloc symbols are correct the addresses
	for (int i = 0; i < file->num_symbols; i++) {
		rsymbol sym = file->symbols[i];
		if (!R_RELOC(sym.type)) continue;
		for (int j = 0; j < disassembler->num_instructions; j++) {
			r_disasm * disas = disassembler->instructions[j];
			int len = 0;
			if (r_meta_find_addr(disas->metadata, sym.addr64, META_ADDR_DATA)) {
				sym.addr64 = disas->address;
				sym.type = R_FUNC;
				file->symbols[i] = sym;
			} else if (r_meta_isaddr(disas->metadata->comment, &len)) {
				//Check if the comment is an address (for rip relative relocs)
				int base = 16;
				if (strlen(disas->metadata->comment) > 2 && (disas->metadata->comment[1] == 'x' || disas->metadata->comment[1] == 'X')) base = 0;
				uint64_t num = (uint64_t)strtol(disas->metadata->comment, NULL, base);
				if (num == sym.addr64) {
					sym.addr64 = disas->address;
					sym.type = R_FUNC;
					file->symbols[i] = sym;
				}
			}
		}				
	}
}

void r_meta_symbol_replace(r_disassembler * disassembler, r_file * file)
{
	char buf[256];
	memset(buf, 0, 256);
	//Add labels for code that is the address of a file symbol
	//And Find references to symbols and replace address with symbol name
	for (int j = 0; j < disassembler->num_instructions; j++) {
		r_disasm * disas = disassembler->instructions[j];
		for (int i = 0; i < file->num_symbols; i++) {
			rsymbol  sym = file->symbols[i];
			if (!sym.name) continue;
			int idx = 0;
			if ((idx=r_meta_find_addr(disas->metadata, sym.addr64, META_ADDR_BOTH) && !disas->metadata->comment)) {
				idx--;
				int ridx = 0;
				for (int k = 0; k < disas->num_operands; k++) {
					int len = 0;
					if (r_meta_isaddr(disas->op[k], &len)) {
						if (idx==ridx) {
							ridx = k;
							break;
						}
						ridx++;
					}
				}
				//sym. means func replaced with symbol name already
				if (disas->op[ridx]) {
					disas->metadata->comment = disas->op[ridx];
					disas->op[ridx] = NULL;
					//free(disas->op[0]);
				}
				disas->op[ridx] = strdup(sym.name);
				
			}
			if (!disas->metadata->label && sym.type == R_FUNC && disas->address == sym.addr64) {
				snprintf(buf, 256, "%s", sym.name);
				disas->metadata->label = strdup(buf);
			}
		}
	}
}

void r_meta_string_replace(r_disassembler * disassembler, r_file * file)
{
	char buf[256];
	memset(buf, 0, 256);
	for (int j = 0; j < disassembler->num_instructions; j++) {
		r_disasm * disas = disassembler->instructions[j];
		//Find references to strings and insert them
		for (int i = 0; i < file->num_strings; i++) {
			int idx = 0;
			if ((disas->metadata->type == r_tdata) && file->strings[i].addr64 != 0 && (idx=r_meta_find_addr(disas->metadata, file->strings[i].addr64, META_ADDR_BOTH))) {
				idx--;
				int ridx = 0;
				for (int k = 0; k < disas->num_operands; k++) {
					int len = 0;
					if (r_meta_isaddr(disas->op[k], &len)) {
						if (idx==ridx) {
							ridx = k;
							int base = 16;
							if (strlen(disas->op[k]) > 2 && (disas->op[k][1] == 'x' || disas->op[k][1] == 'X')) base = 0;
							uint64_t num = (uint64_t)strtol(disas->op[k], NULL, base);
							if (num == file->strings[i].addr64) {
								disas->metadata->comment = disas->op[k];
								disas->op[k] = NULL;
								//free(disas->op[k]);
								snprintf(buf, 256, "\"%s\"", file->strings[i].string);
								disas->op[k] = strdup(buf);
							}
							break;
						}
						ridx++;
					}
				}

			}
		}
	}
}

uint64_t r_meta_get_address(char * operand, int * status)
{
	//Status of 0 means no address found. 1 means address found. 2 Means indirect address found (eg 0x400 vs [0x400])
	*status = 0;
	int len = 0;
	if (r_meta_isaddr(operand, &len)) {
		*status = 1;
		int base = 16;
		if (strlen(operand) > 2 && (operand[1] == 'x' || operand[1] == 'X')) base = 0;
		return (uint64_t)strtol(operand, NULL, base);
	} else {
		*status = 2;
		int size = strlen(operand);
		for (int i = 0; i < size; i++) {
			int len = 0;
			r_meta_isaddr(operand+i,&len);
			//Found the indirect address
			if (operand[i+len] == ']') {
				char * op2 = strdup(operand+i);
				op2[len] = 0;
				int base = 16;
				if (strlen(operand) > 2 && (operand[1] == 'x' || operand[1] == 'X')) base = 0;
				uint64_t n = strtol(op2, NULL, base);
				free(op2);
				return n;
			}
			*status = 0;
		}
	}	
	return 0;
}

//Returns 1 if the string is an address, 0 if it is not. Sets length to the number of characters that are a valid string
int r_meta_isaddr(char * operand, int * len)
{
	if (!operand) return 0;

	int s = strlen(operand);
	for (int i = 0; i < s; i++) {
		*len = i;
		//Empty if statements just for the sake of not having a very long line
		if (operand[i] >= 0x30 && operand[i] < 0x40) continue;
		else if(operand[i] >= 'a'  && operand[i] <= 'f') continue;
		else if (operand[i] >= 'A' && operand[i] <= 'F') continue;
		else if (i == 1 && operand[0] == '0' && (operand[i] == 'x' || operand[i] == 'X')) continue;
		else return 0;
	}

	return 1;
}

int r_meta_rip_relative(char * operand)
{
	if (!operand) return 0;

	int s = strlen(operand);
	for (int i = 0; i < s; i++) {
		if (!strncmp(operand + i, "rip", 3)) {
			char c = operand[i+3];
			if (c != '-' && c != '+') continue;

			char * opaddr = strdup(operand+i+4);
			//rip operands are usually like [rip+0xaddr] so remove ']' at the end
			int len = 0;////
			r_meta_isaddr(opaddr, &len);
			//It is a valid address up until the ']' indirect part
			if (opaddr[len]==']') {
				opaddr[len] = 0;
				int base = 16;
				if (strlen(opaddr) > 2 && (opaddr[1] == 'x' || opaddr[1] == 'X')) base = 0;
				
				uint64_t num = (uint64_t)strtol(opaddr, NULL, base);
				free(opaddr);
				if (c == '-') num = -num;
				return num;
			}
			free(opaddr);
		}
	}

	return 0;
}


void r_add_xref(r_disasm * to, r_disasm * from, int type)
{
	for (int i = 0; i < from->metadata->num_xreffrom; i++) {
		if (from->metadata->xref_from[i].addr == to->address) return;
	}

	from->metadata->num_xreffrom++;
	if (from->metadata->num_xreffrom == 1) {
		from->metadata->xref_from = malloc(sizeof(r_xref));
	} else {
		from->metadata->xref_from = realloc(from->metadata->xref_from, sizeof(r_xref) * from->metadata->num_xreffrom);
	}
	r_xref xfrom;
	xfrom.addr = to->address;
	xfrom.type = to->metadata->type;
	xfrom.addr_type = type;
	from->metadata->xref_from[from->metadata->num_xreffrom-1] = xfrom;

	to->metadata->num_xrefto++;
	if (to->metadata->num_xrefto == 1) {
		to->metadata->xref_to = malloc(sizeof(r_xref));
	} else {
		to->metadata->xref_to = realloc(to->metadata->xref_to, sizeof(r_xref) * to->metadata->num_xrefto);
	}
	r_xref xto;
	xto.addr = from->address;
	xto.type = from->metadata->type;
	xto.addr_type = type;
	to->metadata->xref_to[to->metadata->num_xrefto-1] = xto;
}

void r_meta_find_xrefs(r_disassembler * disassembler, r_file * file)
{
	for (int i = 0; i < disassembler->num_instructions; i++) {
		r_disasm * instr1 = disassembler->instructions[i];

		for (int j = 0; j < disassembler->num_instructions; j++) {
			if (j==i) continue;
			r_disasm * instr2 = disassembler->instructions[j];

			for (int k = 0; k < instr2->metadata->num_addr; k++) {
				if (instr2->metadata->addresses[k] == instr1->address) {
					//only use code xrefs
					r_add_xref(instr1, instr2, instr2->metadata->address_types[k]);
				}
			}
		}
	}	
}

r_analyzer * r_analyzer_init()
{
	r_analyzer * anal = malloc(sizeof(r_analyzer));

	anal->num_functions = 0;
	anal->functions = NULL;
	anal->num_branches = 0;
	anal->branches = NULL;
	anal->function = 1;

	return anal;
}


void r_analyzer_destroy(r_analyzer * anal)
{
	if (!anal) return;
	
	for (int i = 0; i < anal->num_functions; i++) {
		free(anal->functions[i].name);
		for (int j = 0; j < anal->functions[i].argc; j++) {
			free(anal->functions[i].args[j]);
		}
		free(anal->functions[i].args);
	}
	for (int i = 0; i < anal->num_branches; i++) {

	}

	free(anal->functions);
	free(anal->branches);
	free(anal);
}

void r_function_arguments(r_disassembler * disassembler, r_analyzer * anal, r_function * func, r_abi abi)
{
	/*
	CALLING CONVENTIONS: unix64
	RDI=arg1
	RSI=arg2
	RDX=arg3
	RCX=arg4
	R8 =arg5
	R9 =arg6
	STCK= other args
	IDENTIFYING USED ARGS:
	
	mov rsi, 1
	mov rdi, 0
	call func
	...
	func:
	push rbp
	mov rbp, rsp
	sub rsp, 0x20
	mov qword [rbp-0x14], rdi
	mov qword [rbp-0x20], rsi
	..
	ARGS = func(0, 1)
	
	Goto Function and identify what possible registers that hold arguments are used.
	*/

	//Only using 
	if (abi != rc_sysv64 && abi != rc_sysv32) {
		printf("Argument recognition is wip and only supports System V ABI right now\n");
		return;
	}

	int rdist = 10;
	int argc = 0;
	int * args = NULL;

	/*Goto the function address*/
	for (int i = 0; i < disassembler->num_instructions; i++) {
		r_disasm * disas = disassembler->instructions[i];
		if (disas->address < func->start) continue;
		if (disas->address > (func->start + func->size)) break;
		rdist--;
		if (disas->metadata->type != r_tdata && disas->metadata->type != r_tpush && disas->metadata->type != r_tpop) continue;

		int arg = 0;
		//source is farthest right operand so use next to last
		for (int j = (disas->num_operands-1); j < disas->num_operands; j++) {
			int b = x_register_index(disas->op[j]);
			//if (b==-1) continue;
			for (int k = 0; k < (sizeof(unix64_cc)/sizeof(char*)); k++) {
				int a = x_register_index(unix64_cc[k]);
				if (a==-1 && b == -1) {//Works for i386 SysV too if you ignore the 64 bit register parameter
					//Perhaps on the stack
					int d = r_function_get_stack_args(disas->op[j], abi);
					if (d!=-1) {
						int used = 0;
						for (int n = 0; n < argc; n++) {
							if (args[n]==-d) {
								used = 1;
								break;
							}
						}
						if (used) break;
						arg = k;					
						argc++;
						if (argc == 1) {
							args = malloc(sizeof(int));
						} else {
							args = realloc(args, sizeof(int)*argc);
						}
						args[argc-1] = -d;
					}
				} else if (a==-1 || rdist < 0) continue; //After rdist assume that register are used for other reason
				else if (abi == rc_sysv64 && X_REG_BIN(a) == X_REG_BIN(b)) {//X86_64 SysV only
					int used = 0;
					for (int n = 0; n < argc; n++) {
						if (X_REG_BIN(args[n])==X_REG_BIN(b)) {
							used = 1;
							break;
						}
					}
					if (used) break;
					arg = k;					
					argc++;
					if (argc == 1) {
						args = malloc(sizeof(int));
					} else {
						args = realloc(args, sizeof(int)*argc);
					}
					args[argc-1] = (b);
					break;
				}
			}
		}
	}
	/*For now only supporting register arguments*/
	func->argc = argc;
	func->args = malloc(argc * sizeof(char*));
	for (int i = 0; i < argc; i++) {
		int r = args[i];
		if (r<0) {
			char buf[32];
			snprintf(buf, 32, "%#x", -r);
			func->args[i] = strdup(buf);
			continue;
		} else {
			func->args[i] = strdup(x64_general_registers[r]);
		}
	}
	free(args);
}

//This function determines if the current instruction is using an argument on the stack
//Returns the displacment if it is otherwise returns -1
int r_function_get_stack_args(char * operand, r_abi abi)
{
	if (abi != rc_sysv64 && abi != rc_sysv32) return -1;

	int m_disp = abi==rc_sysv64?8:4;
	int disp = 0;
	int s = strlen(operand);
	for (int i = 0; i < s; i++) {
		/*According to systemV abi the return address is directly ontop of the stack (4 bytes for 32 bit systems and 8 bytes for 64 bit)
		Then above that are arguments
		*/
		if (!strncmp(operand + i, "ebp", 3) || !strncmp(operand + i, "rbp", 3)) {
			char c = operand[i+3];
			if (c != '+') continue;
			char * opaddr = strdup(operand+i+4);
			//rip operands are usually like [rip+0xaddr] so remove ']' at the end
			int len = 0;////
			r_meta_isaddr(opaddr, &len);
			//It is a valid address up until the ']' indirect part
			if (opaddr[len]==']') {
				opaddr[len] = 0;
				int base = 16;
				if (strlen(opaddr) > 2 && (opaddr[1] == 'x' || opaddr[1] == 'X')) base = 0;
				
				uint64_t num = (uint64_t)strtol(opaddr, NULL, base);
				free(opaddr);
				//Check if above return address
				if (num <= m_disp) continue;
				return num;
			}
			free(opaddr);
		}
	}

	return -1;
}

void r_function_arg_replacer(r_disassembler * disassembler, int idx, r_function * func, r_abi abi)
{
	/*
	Attempt to find parameters of call instruction by using function data and the calling convention
	*/
	if (abi != rc_sysv64 && abi != rc_sysv32) {
		printf("Argument recognition is very much wip and only supported using unix64 calling convention\n");
		disassembler->instructions[idx]->op[0] = strdup("()");
		return;
	}
	int ret_addr = abi==rc_sysv64?8:4;
	char buf[256];
	int iter = 0;
	memset(buf, 0, 256);
	int search_len = 10;
	iter += snprintf(buf+iter, 256-iter, "%s(", func->name);
	int nargc = 0;
	r_disasm * disas = NULL;
	/*Goto the function address*/
	for (int i = (idx-1); i >=0 && i > (idx-search_len);i--) {
		disas = disassembler->instructions[i];
		if (disas->metadata->type != r_tdata && disas->metadata->type != r_tpush && disas->metadata->type != r_tpop) continue;

		int found = 0;
		//destination is farthest left operand so use next to last
		for (int j = 0; j < disas->num_operands && j < 1; j++) {
			int b = x_register_index(disas->op[j]);
			//if (b==-1) continue;
			for (int k = 0; k < func->argc; k++) {
				int a = x_register_index(func->args[k]);
				if (a==-1 && disas->metadata->type == r_tpush) {
					found = 1;
					int n = (j+1)<disas->num_operands ? j+1 : j;
					if (nargc != 0) iter += snprintf(buf+iter, 256-iter, ", ");
					iter += snprintf(buf+iter, 256-iter, "%s", disas->op[n]);
					nargc++;
					break;				
				} else if (disas->metadata->type != r_tpush && X_REG_BIN(a) == X_REG_BIN(b)) {
					found = 1;
					int n = (j+1)<disas->num_operands ? j+1 : j;
					if (nargc != 0) iter += snprintf(buf+iter, 256-iter, ", ");
					iter += snprintf(buf+iter, 256-iter, "%s", disas->op[n]);
					nargc++;
					break;
				}
			}
		}
		if (nargc == func->argc) break;
		if (!found) break;
	}
	disas = disassembler->instructions[idx];
	iter += snprintf(buf+iter, 256-iter, ")");
	if (disas->num_operands > 0) {
		if (disas->op[0]) free(disas->op[0]);
		disas->op[0] = strdup(buf);
	}
}