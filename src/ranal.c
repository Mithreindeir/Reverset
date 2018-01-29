#include "ranal.h"

void r_add_xref(r_disasm * to, r_disasm * from)
{
	
}

void r_meta_analyze(r_disasm ** disassembly, int num_instructions, rfile * file)
{
	//General purpose buffer
	char buf[256];
	memset(buf, 0, 256);
	
	//Add labels for code that is the address of a file symbol
	//And Find references to symbols and replace address with symbol name
	for (int j = 0; j < num_instructions; j++) {
		r_disasm * disas = disassembly[j];
		for (int i = 0; i < file->num_symbols; i++) {
			rsymbol  sym = file->symbols[i];
			if (disas->metadata->type == r_tcall && sym.type == R_FUNC && r_meta_find_addr(disas->metadata, sym.addr64, META_ADDR_BRANCH)) {
				if (disas->op[0]) {
					disas->metadata->comment = disas->op[0];
					disas->op[0] = NULL;
					//free(disas->op[0]);
				}
				disas->op[0] = strdup(sym.name);
			}
			if (sym.type == R_FUNC && disas->address == sym.addr64) {
				snprintf(buf, 256, "sym.%s", sym.name);
				disas->metadata->label = strdup(buf);
			}
		}

		//Find references to strings and insert them
		for (int i = 0; i < file->num_strings; i++) {
			if ((disas->metadata->type == r_tdata) && file->strings[i].addr64 != 0 && r_meta_find_addr(disas->metadata, file->strings[i].addr64, META_ADDR_DATA)) {
				for (int k = 0; k < disas->num_operands; k++) {
					if (r_meta_isaddr(disas->op[k])){
						int base = 16;
						if (strlen(disas->op[k]) > 2 && (disas->op[k][1] == 'x' || disas->op[k][1] == 'X')) base = 0;
						uint64_t num = (uint64_t)strtol(disas->op[k], NULL, base);
						if (num == file->strings[i].addr64) {
							disas->metadata->comment = disas->op[k];
							disas->op[k] = NULL;
							//free(disas->op[k]);
							snprintf(buf, 256, " \"%s\"", file->strings[i].string);
							disas->op[k] = strdup(buf);
						}
					}
					
				}
			}
		}
	}
	if (file->arch == r_x86_64) {
		//Add comments for RIP relative addresses (x64 only)
		for (int j = 0; j < num_instructions; j++) {
			r_disasm * disas = disassembly[j];
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
}

int r_meta_isaddr(char * operand)
{
	if (!operand) return 0;

	int s = strlen(operand);
	for (int i = 0; i < s; i++) {
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
		if (!strncmp(operand + i, "rip+", 4)) {
			char * opaddr = strdup(operand+i+4);
			//rip operands are usually like [rip+0xaddr] so remove ']' at the end
			for (int j=0; j < strlen(opaddr); j++) if (opaddr[j]==']') opaddr[j]=0;
			if (r_meta_isaddr(opaddr)) {
				int base = 16;
				if (strlen(opaddr) > 2 && (opaddr[1] == 'x' || opaddr[1] == 'X')) base = 0;
				return (uint64_t)strtol(opaddr, NULL, base);
			}
		}
	}

	return 0;
}