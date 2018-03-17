#include "x86assembler.h"

unsigned char * x86_assemble(char * instr, uint64_t addr_s, int * num_bytes)
{
	uint32_t addr = addr_s;
	//printf("input: %s\n", instr);
	char * instruction = strdup(instr);
	char * mnemonic = NULL;
	char ** operands = NULL;
	int num_operands = 0;

	int len = strlen(instruction);

	int chars = -1;
	struct x86_asm_bytes * xasm = malloc(sizeof(struct x86_asm_bytes));
	xasm->bytes = NULL;
	xasm->num_bytes = 0;
	//Rudimentary parser.
	//Sets first token as mnemonic
	int i = 0;
	for (; i < len+1; i++) if (instr[i]!=' ' && instr[i]!='\n' && instr[i]!='\t') break;
	if (i >= (len)) {
		free(instruction);
		free(xasm);
		return NULL;
	}

	//First operands are delimited by a comma, the last is delimited by a NULL character
	for (; i < len+1; i++) {

		if (mnemonic) {
			//If mnemonic is a prefix then set the mnemonic back to null and add prefix byte
			for (int j = 0; j < sizeof(x86_instr_prefix_str)/sizeof(char*); j++) {
				if (!x86_instr_prefix_str[j]) continue;
				if (!strcmp(mnemonic, x86_instr_prefix_str[j])) {
					x86_add_byte_prefix(xasm, x86_instr_prefix_byte[j]);
					mnemonic = NULL;
					chars = -1;
					break;
				}
			}

		}
		//Set the mnemonic to the first word that has a space after it.
		if ((instruction[i] == 0 || instruction[i] == ' ') && !mnemonic) {
			instruction[i] = 0;
			if (chars != -1) {
				char * str = no_space_strdup(instruction+chars);
				if (!mnemonic) mnemonic = str;
			}
			chars = -1;
		} else if (instruction[i] == ',') {
			instruction[i] = 0;
			if (chars != -1) {
				char * str = no_space_strdup(instruction+chars);
				num_operands++;
				if (num_operands == 1) {
					operands = malloc(sizeof(char*));
				} else {
					operands = realloc(operands, sizeof(char*) * num_operands);
				}
				operands[num_operands-1] = str;
			}
			chars = -1;
		} else if (instruction[i] == 0) {
			instruction[i] = 0;
			if (chars != -1) {
				char * str =  no_space_strdup(instruction+chars);
				num_operands++;
				if (num_operands == 1) {
					operands = malloc(sizeof(char*));
				} else {
					operands = realloc(operands, sizeof(char*) * num_operands);
				}
				operands[num_operands-1] = str;
			}
			chars = -1;
		} else if (chars == -1) chars = i;
	}

	struct x86_assemble_op * modes = malloc(sizeof(struct x86_assemble_op) * num_operands);

	for (int i = 0; i < num_operands; i++) {
		modes[i] = x86_assembler_type(operands[i]);
		modes[i].operand = operands[i];
	}
	int extended = -1;
	int opc = x86_find_instruction(xasm, mnemonic, addr, modes, num_operands, &extended);
	if (opc != -1) {
		x86_instruction instr = x86_instruction_table[opc];
	} else {
		free(xasm);
		for (int i = 0; i < num_operands; i++) {
			free(modes[i].operand);
		}
		free(operands);
		free(mnemonic);
		free(modes);
		free(instruction);
		printf("Unable to assemble instruction\n");
		return NULL;
	}
	x86_add_byte(xasm, opc);

	x86_encode_modrm(xasm, modes, num_operands, extended);
	for (int i = 0; i < num_operands; i++) {
		if (X86_NUMBER_OP(modes[i].mode) && modes[i].mode != X86_REL) {
			if (modes[i].size == X86_BYTE) {
				unsigned char c = strtol(modes[i].operand, NULL, 0);
				x86_add_byte(xasm, c);
			} else if (modes[i].size == X86_WDWORD || modes[i].size == X86_DWORD) {
				uint32_t c = (uint32_t)strtol(modes[i].operand,NULL,0);
				x86_add_int32(xasm, c);
			}
		} else if (modes[i].mode == X86_REL) {
			uint32_t c = strtol(modes[i].operand, NULL, 0);
			c -= addr + xasm->num_bytes;
			if (modes[i].relative_size == X86_BYTE) {
				c -= 1;
				x86_add_byte(xasm, (unsigned char)c);
			} else if (modes[i].relative_size == X86_WDWORD || modes[i].relative_size == X86_DWORD) {
				c -= 4;
				x86_add_int32(xasm, c);
			}
		}
	}

	for (int i = 0; i < num_operands; i++) {
		free(modes[i].operand);
	}

	free(operands);
	free(mnemonic);
	free(modes);
	free(instruction);
	unsigned char * bytes = xasm->bytes;
	*num_bytes = xasm->num_bytes;
	free(xasm);
	return bytes;
}

void x86_encode_modrm(struct x86_asm_bytes * asm_op, struct x86_assemble_op * operands, int num_operands, int extended)
{
	unsigned char modrm = 0;
	//Code extended into modrm
	if (extended!=-1) {
		modrm |= (extended<<3);
	}
	int modop = -1;
	//If there is a reg operand then set it in the modrm byte
	for (int i = 0; i < num_operands; i++) {
		if (operands[i].mode == X86_REG) {
			int reg = x86_register_index(operands[i].operand);
			char r = X86_REG_BIN(reg);

			modrm |= (r<<3);
		}

		if (operands[i].mode == X86_MODRM) modop = i;
	}
	if (modop != -1) {
		//If the operand is direct addressing a register then mod = 11 and r/m = reg
		int reg = x86_register_index(operands[modop].operand);
		if (reg != -1) {
			modrm |= MODRM_REGISTER << 6;
			int r = X86_REG_BIN(reg);
			operands[modop].opr_size = X86_REG_SIZE(reg);
			modrm |= r;
			x86_add_byte(asm_op, modrm);
		} else {
			//Either SIB or reg+displacement
			//Check for reg+displacement
			struct x86_indirect indir;
			x86_retrieve_indirect(operands[modop].operand, &indir);
			if (indir.sib) {
				modrm |= MODRM_SIB;
				if (indir.disp_size == 1) modrm |= 0x1<<6;
				else if (indir.disp_size == 4) modrm |= 0x2<<6;
				char sib = 0;
				if (indir.scale != -1)
					sib |= x86_scale(indir.scale)<<6;
				if (indir.index != -1)
					sib |= indir.index<<3;
				else sib |= 0x4<<3;	//ESP is an invalid index so use that if no index
				if (indir.base != -1)
					sib |= indir.base;
				else {//Only way to not use base is to set base to EBP and use disp32
					sib |= 5;
					if (indir.disp_size == 0) {
						indir.disp_size = 4;
						indir.disp = 0;
					}
					else indir.disp_size = 4;
					//disp means forced mod of 0
					//1100 0000 = 0xc0
					modrm ^= modrm&0xc0;
				}
				x86_add_byte(asm_op, modrm);
				x86_add_byte(asm_op, sib);
				if (indir.disp_size==1) x86_add_byte(asm_op, (unsigned char)indir.disp);
				else if (indir.disp_size==4) {
					x86_add_int32(asm_op, indir.disp);
				}
			} else {
				if (indir.base != -1 && indir.disp_size == 0) modrm |= MODRM_INDIRECT << 6;
				else if (indir.base != -1 && indir.disp_size == 1) modrm |= MODRM_ONEBYTE << 6;
				else if (indir.base != -1 && indir.disp_size == 4) modrm |= MODRM_FOURBYTE << 6;

				if (indir.base != -1) {
					modrm |= indir.base;
				}

				operands[modop].addr_size = indir.addr_size;

				x86_add_byte(asm_op, modrm);
				if (indir.disp_size==1) x86_add_byte(asm_op, (unsigned char)indir.disp);
				else if (indir.disp_size==4) {
					x86_add_int32(asm_op, indir.disp);
				}
			}
		}
	}
}

int x86_scale(int scalef)
{
	if (scalef == 8) return 3;
	else if (scalef == 4) return 2;
	else if (scalef == 2) return 1;
	else return 0;
}

void x86_retrieve_indirect(char * operand, struct x86_indirect * indir)
{
	char * base = NULL;
	char * index = NULL;
	char * scale = NULL;
	char * displacement = NULL;
	unsigned char disp8 = 0;
	uint32_t disp32 = 0;
	int neg = 0;
	int size = 0;
	char * prefix = strtok_dup(operand, "[", 0);
	indir->disp = 0;
	indir->sib = 0;

	if (prefix) {
		char * body = strtok_dup(NULL, "]", 0);
		char * before = NULL;
		before = strtok_dup(body, "+0x", 0);

		if (!before) {
			before = strtok_dup(body, "-0x", 0);
			if (before) {
				displacement = strtok_dup(NULL, " ", 1);
				neg = 1;
			}
		} else {
			displacement = strtok_dup(NULL, "", 1);
		}

		if (displacement) {
			if (strlen(displacement) > 4) {
				disp32 = strtol(displacement, NULL, 0);
				if (neg) disp32 = -disp32;
				size = 3;
			} else {
				disp8 = strtol(displacement, NULL, 0);
				if (neg) disp8 = -disp8;
				size = 1;
			}
		}
		//printf("body: %s\ndisp: %#x %#x\n", before, disp8, disp32);
		base = strtok_dup(before, "+", 0);
		if (base) {
			index = strtok_dup(NULL, "*", 0);
			if (index) {
				scale = strtok_dup(NULL, " ", 1);
			}
		} else {
			char * tmp = strtok_dup(NULL, "*", 0);
			if (tmp) {
				index = tmp;
				scale = strtok_dup(NULL, " ", 1);
			} else {
				base = strtok_dup(NULL, " ", 1);
			}
		}

		//In disponly cases, base will be a number
		if (base && !index && !scale && !displacement) {
			int is_reg = x86_register_index(base);
			//If base is not a register then swap it with displacement
			if (is_reg==-1) {
				displacement = base;
				if (strlen(displacement) > 4) {
					disp32 = strtol(displacement, NULL, 0);
					if (neg) disp32 = -disp32;
					size = 3;
				} else {
					disp8 = strtol(displacement, NULL, 0);
					if (neg) disp8 = -disp8;
					size = 1;
				}
				base = NULL;
			}
		}
		indir->addr_size = 0;
		if (index || scale) indir->sib = 1;

		if (index) {
			int i = x86_register_index(index);
			if (i==-1) indir->index = -1;
			else indir->index = X86_REG_BIN(i);
			indir->addr_size = X86_REG_SIZE(i);
		} else indir->index = -1;

		if (scale) {
			indir->scale = strtol(scale,NULL,16);
		} else indir->scale = -1;

		if (base) {
			int b = x86_register_index(base);

			if (b==-1) indir->base = -1;
			else indir->base = X86_REG_BIN(b);
			indir->addr_size = X86_REG_SIZE(b);
			//ESP forced sib
			if (X86_REG_BIN(b) == 0x4) indir->sib = 1;

		} else indir->base = -1;

		if (displacement) {
			if (size == 3) {
				indir->disp_size = 4;
				indir->disp = disp32;
			} else {
				indir->disp_size = 1;
				indir->disp = disp8;
			}
		} else indir->disp_size = 0;

		if (index) free(index);
		if (scale) free(scale);
		if (base) free(base);
		if (before) free(before);
		if (displacement) free(displacement);
		if (body) free(body);
		free(prefix);
	}
	//printf("%x %x %x %x", indir->base, indir->index, indir->scale, indir->disp);
	//getchar();
}

struct x86_assemble_op x86_assembler_type(char * operand)
{
	struct x86_assemble_op op;
	op.addr_size = 0;
	op.mode = 0;
	op.size = 0;
	int size = 0;
	int indir_size = x86_indirect_prefix(operand);
	//Indir size of anything other than 0 means it is an indirect addressing mode
	if (indir_size) {
		size = indir_size;
		op.opr_size = size;
		op.mode = X86_MODRM;
		//All indirect size prefixs are 5 except byte which is four, so adjust operand index accordingly
		//x86_encode_modrm(oper, operand + 4+(indir_size!=1));
	} else if (operand[0] == '0' && operand[1] == 'x') {
		//The operand is immediate, relative, or a moffset
		int s = strlen(operand);
		if (s <= 5) size = 1;
		else size = 3;
		op.opr_size = size;
		op.mode = X86_IMM;
	} else {
		//The operand is a register
		int reg = x86_register_index(operand);
		if (reg!=-1) {
			size = X86_REG_SIZE(reg);
		}
		op.mode = X86_REG;
	}

	if (size == 3 || size == 4) {
		op.size = X86_WDWORD;
	} else if (size == 2) {
		op.size = X86_BWORD;
	} else if (size == 1) {
		op.size = X86_BYTE;
	}
	return op;
}

int x86_relative_size(char * operand, uint32_t address)
{
	uint32_t rel = strtol(operand, NULL, 0) - address;
	if ((signed int)(rel >> 8) <= 0) return X86_BYTE;
	if ((signed int)(rel >> 16) <= 0) return X86_WORD;

	return X86_WDWORD;
}

//Checks for indirect size prefix
int x86_indirect_prefix(char * operand)
{
	if (!strncmp(operand, "dword", 5)) {
		return 3;
	} else if (!strncmp(operand, "word", 4)) {
		return 2;
	} else if (!strncmp(operand, "byte", 4)) {
		return 1;
	}
	return 0;
}

int x86_register_index(char * reg)
{
	//(uses same register array as 64 bit)
	for (int i = 0; i < sizeof(x64_general_registers)/sizeof(char*); i++) {
		if (!strncmp(reg, x64_general_registers[i], strlen(x64_general_registers[i])))
			return i;
	}
	return -1;
}

int x86_find_instruction(struct x86_asm_bytes * asm_op, char * mnemonic, uint32_t addr, struct x86_assemble_op * operands, int num_operands, int * extended)
{

	x86_instruction instr;
	for (int i = 0; i < (sizeof(x86_instruction_table)/sizeof(x86_instruction)); i++) {
	 	instr = x86_instruction_table[i];
	 	//if part of a group then iterate through that
		if (!strncmp("grp", instr.mnemonic, 3)) {
			char group = instr.mnemonic[3]-0x30 -1;
			char opr = instr.mnemonic[4];
			//Some groups all share the same operands, other differ. 'd' means use the default given by the group operand. a means use the operands in group table a and b means group table b and etc

			for (int j = 0; j < 8; j++) {
				instr = x86_instruction_table[i];
				if (opr == 'd') {
					instr.mnemonic = x86_groups[group][j].mnemonic;
				} else if (opr == 'a') {
					instr = x86_groups[group][j];
				} else if (opr == 'b') {
					instr = x86_groups[group][j+GROUP_OFFSET];
				}
				if (!instr.mnemonic[0]) continue;

				if (!strcmp(mnemonic, instr.mnemonic)) {
					if (x86_operands_compatible(instr, addr, operands, num_operands)) {
						*extended = j;
						return i;
					}
				}
			}
		}
		if (!strcmp(mnemonic, instr.mnemonic)) {
			if (x86_operands_compatible(instr, addr, operands, num_operands)) {
				return i;
			}

		}
	}

	for (int i = 0; i < (sizeof(x86_instruction_extended_table)/sizeof(x86_instruction)); i++) {
	 	instr = x86_instruction_extended_table[i];
	 	//if part of a group then iterate through that
		if (!strncmp("grp", instr.mnemonic, 3)) {
			char group = instr.mnemonic[3]-0x30 -1;
			char opr = instr.mnemonic[4];
			//Some groups all share the same operands, other differ. 'd' means use the default given by the group operand. a means use the operands in group table a and b means group table b and etc

			for (int j = 0; j < 8; j++) {
				instr = x86_instruction_table[i];
				if (opr == 'd') {
					instr.mnemonic = x86_groups[group][j].mnemonic;
				} else if (opr == 'a') {
					instr = x86_groups[group][j];
				} else if (opr == 'b') {
					instr = x86_groups[group][j+GROUP_OFFSET];
				}
				if (!instr.mnemonic[0]) continue;

				if (!strcmp(mnemonic, instr.mnemonic)) {
					if (x86_operands_compatible(instr, addr, operands, num_operands)) {
						*extended = j;
						x86_add_byte_prefix(asm_op, 0x0f);
						return i;
					}
				}
			}
		}

		if (!strcmp(mnemonic, instr.mnemonic)) {
			if (x86_operands_compatible(instr, addr, operands, num_operands)) {
				x86_add_byte_prefix(asm_op, 0x0f);
				return i;
			}

		}
	}


	return -1;
}

//G, G is analagous to both G, E and E, G
//But G, E != E, G or G, G or E, E
int x86_operands_compatible(x86_instruction instr, uint32_t addr, struct x86_assemble_op * operands, int num_operands)
{
	int num_ops = 0;
	for (;num_ops < 3; num_ops++) {
		if (!strlen(instr.op[num_ops])) break;
	}
	if (num_ops != num_operands) return 0;

	int inequal = 0;
	int switchge = -1;
	for (int i = 0; i < num_ops; i++) {
		int m2 = instr.op[i][0];//Retrieves addressing mode
		int s2 = instr.op[i][1];//Retrieves operand size

		//X86_MEM is an altered version of m
		if (m2 == X86_MEM) m2 = X86_MODRM;

		if (operands[i].mode != m2) {
			//Use this opportunity to set operand size possible
			if (!strcmp(operands[i].operand, instr.op[i])) {
				int r = x86_register_index(operands[i].operand);
				if (r!=-1) operands[i].opr_size = X86_REG_SIZE(r);
				continue;
			}
			//G can also be a E if there is no other E
			if (operands[i].mode == X86_REG && m2 == X86_MODRM) {
				int other_e = 0;
				for (int j = 0; j < num_ops; j++) {
					if (operands[i].mode == X86_MODRM) other_e = 1;
				}
				if (other_e) return 0;
			} else if ((X86_NUMBER_OP(operands[i].mode) && X86_NUMBER_OP(m2)));//Immediate, relative and moffset are all same string so make them all compatible
			else return 0;
		}
		int size = operands[i].size;
		if (m2 == X86_REL) {
			int a_size = (size == X86_BYTE) ? 1 : 4;
			operands[i].relative_size = x86_relative_size(operands[i].operand, addr+1+a_size);
			size = operands[i].relative_size;
		}

		if (s2 && !x86_size_compatible(m2, size, s2)) return 0;
	}

	//If the two instruction are compatible, then set the valid mode and size
	for (int i = 0; i < num_ops; i++) {
		int m2 = instr.op[i][0];
		int s2 = instr.op[i][1];
		if (m2 == X86_MEM) m2 = X86_MODRM;

		operands[i].mode = m2;
		if (s2) operands[i].size = s2;
	}

	return 1;
}

int x86_size_compatible(int type, int size1, int size2)
{
	if (size1 == size2) return 1;
	if (size1 == 'v' && (size2 == 'd' || size2 == 'w')) return 1;
	if (size2 == 'v' && (size1 == 'd' || size1 == 'w')) return 1;
	//Number types are always upwards compatible (0x0 can be a byte, word, dword or qword)
	if (0 &&X86_NUMBER_OP(type) && type != X86_REL) {
		if (size1 == 'b' && (size2 == 'w' || size2 == 'd' || size2 == 'v')) return 1;
		if (size1 == 'w' && (size2 == 'd' || size2 == 'v')) return 1;
		if (size1 == 'd' && (size2 == 'v')) return 1;
	}
	return 0;
}

void x86_add_byte(struct x86_asm_bytes * op, unsigned char byte)
{
	op->num_bytes++;
	if (op->num_bytes==1) {
		op->bytes = malloc(1);
	} else {
		op->bytes = realloc(op->bytes, op->num_bytes);
	}
	op->bytes[op->num_bytes-1] = byte;
}

void x86_add_byte_prefix(struct x86_asm_bytes * op, unsigned char byte)
{
	op->num_bytes++;
	if (op->num_bytes==1) {
		op->bytes = malloc(1);
	} else {
		op->bytes = realloc(op->bytes, op->num_bytes);
		memmove(op->bytes+1, op->bytes, op->num_bytes-1);
	}
	op->bytes[0] = byte;
}

void x86_add_int32(struct x86_asm_bytes * op, uint32_t bint)
{
	unsigned char * dchar = (unsigned char*)&bint;
	for (int i = 0; i < 4; i++) {
		x86_add_byte(op, dchar[i]);
	}
}
