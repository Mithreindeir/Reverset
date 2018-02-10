#include "x64disassembler.h"

x64_instr_prefix x64_instruction_prefix(unsigned char * stream, int * len)
{
	x64_instr_prefix prefix;
	prefix.size_override = 0;
	prefix.addr_override = 0;
	prefix.segment_register = NULL;
	prefix.instr_prefix = NULL;
	prefix.extended = 0;
	prefix.rex_prefix = 0;

	int prefix_found = 0;
	do {
		prefix_found = 0;
		char c = stream[*len];
		//Check for opcode extension prefix (0F)
		if (c==0x0F) {
			prefix_found = 1;
			prefix.extended = 1;
			(*len)++;
			break;
		}
		//Check for rex
		if (X64_REX_PREFIX(c)) {
			prefix_found = 1;
			prefix.rex_prefix = c-0x40;
			(*len)++;
			continue;
		}

		//Check for rep, repne, lock or size override bytes
		int type = 0;
		for (int i = 0; i < (sizeof(x86_instr_prefix_byte)); i++) {
			if (c == x86_instr_prefix_byte[i]) {
				prefix_found = 1;
				type = i;
				(*len)++;
				continue;
			}
		}
		if (prefix_found) {
			prefix.instr_prefix =  x86_instr_prefix_str[type]; 
			if (type == X64_ADDR_SIZE_OVERRIDE) prefix.addr_override = 1;
			if (type == X64_OPERAND_SIZE_OVERRIDE) prefix.size_override = 1;		
		}
		//Check segment override TODO FIX
		for (int i = 0; i < (sizeof(x86_segment_register_byte)); i++ ) {
			if (c == x86_segment_register_byte[i]) {
				prefix_found = 1;
				prefix.segment_register = x86_segment_registers[i];
				(*len)++;
				continue;
			}
		}
	} while (prefix_found);
	//Check if override
	return prefix;
}

r_disasm * x64_decode_instruction(unsigned char * stream, int address)
{
	int len = 0;
	x64_instr_prefix prefix = x64_instruction_prefix(stream, &len);
	unsigned char instrb = stream[len];
	len++;
	
	x64_disas_state state;
	state.addr_override = prefix.addr_override;
	state.size_override = prefix.size_override;
	state.stream = stream;
	state.iter = &len;
	state.opr_size = 3;
	state.addr_size = 3;
	state.address = address;
	state.operand_start = len;
	state.rex = prefix.rex_prefix;
	state.seg_o = prefix.segment_register != NULL;
	state.seg_reg = prefix.segment_register;
	//Get opcode information from table
	x64_instruction instr;

	if (prefix.extended) instr = x64_instruction_extended_table[instrb];
	else instr = x64_instruction_table[instrb];

	//Check for opcode extension, and correct mnemonic
	if (!strncmp("grp", instr.mnemonic, 3)) {
		char mod = MASK_MODRM_REG(stream[len]);
		char group = instr.mnemonic[3]-0x30 -1;
		char opr = instr.mnemonic[4];
		if (opr == 'd') {
			instr.mnemonic = x64_groups[group][mod].mnemonic;
		} else if (opr == 'a') {
			instr = x64_groups[group][mod];
		} else if (opr == 'b') {
			instr = x64_groups[group][mod+GROUP_OFFSET];
		}
		//Some groups all share the same operands, other differ. 'd' means use the default given by the group operand. a means use the operands in group table a and b means group table b and etc
	}
	x64_instr_operand* op1, *op2,* op3;
	//Decode operands
	op1 = x64_decode_operand(instr.op1, &state);
	op2 = x64_decode_operand(instr.op2, &state);
	op3 = x64_decode_operand(instr.op3, &state);
	int ub = len;
	/*Intermediate functions: Resolve relative addresses and sign extend*/
	if (op1 && op1->type == X64O_REL) op1->relative = x64_resolve_address(op1->relative,address,ub); 
	if (op2 && op2->type == X64O_REL) op2->relative = x64_resolve_address(op2->relative,address,ub); 
	if (op3 && op3->type == X64O_REL) op3->relative = x64_resolve_address(op3->relative,address,ub); 

	x64_sign_extend(op1, op2, op3);

	//Convert instructions to strings 
	int iter = 0;
	char buf[32];
	if (prefix.instr_prefix) iter += snprintf(buf+iter, 32-iter, "%s ", prefix.instr_prefix);
	snprintf(buf+iter, 32-iter, "%s", instr.mnemonic);
	r_disasm * disas = r_disasm_init();
	disas->mnemonic = strdup(buf);
	x64_disas_meta_type(disas);

	//printf("%s ", instr.mnemonic);

	if (op1) {
		x64_disas_meta_operand(disas, op1);
		disas->op[0] = x64_sprint_operand(op1);
		disas->num_operands++;
	}
	if (op2) {
		x64_disas_meta_operand(disas, op2);
		disas->op[1] = x64_sprint_operand(op2);
		disas->num_operands++;
	}
	if (op3) {
		x64_disas_meta_operand(disas, op3);
		disas->op[2] = x64_sprint_operand(op3);
		disas->num_operands++;
	}

	//Free operand data structures
	if (op1) free(op1);
	if (op2) free(op2);
	if (op3) free(op3);

	disas->used_bytes = ub;
	if (strlen(disas->mnemonic) == 0) {
		free(disas->mnemonic);
		disas->mnemonic = strdup("invalid");
		disas->used_bytes = 1;
	}
	disas->raw_bytes = malloc(disas->used_bytes+1);
	disas->raw_bytes[disas->used_bytes] = 0;
	disas->raw_bytes = memcpy(disas->raw_bytes, stream, disas->used_bytes);
	disas->address = address;

	return disas;
}

x64_instr_operand *x64_decode_operand(char * operand, x64_disas_state *state)
{
	if (!operand) return NULL;
	if (strlen(operand) < 1) return NULL;

	x64_instr_operand * opr = malloc(sizeof(x64_instr_operand));
	memset(opr, 0, sizeof(x64_instr_operand));

	//32bit=3 16bit=2 8bit=1. Assume 32 bit mode
	//default size is 32 bit
	int operand_size = 3;
	if (X64_MASK_REX_W(state->rex)) operand_size = 4;
	int address_size = 4 - state->addr_override;
	//A capital first letter means it is an addressing mode
	if (operand[0] >= 'A' && operand[0] <= 'Z') {
		//Calculate operand and address size
		switch(operand[1]) {
			case X64_TWO_WORD:
				printf("Not implemented\n");
				exit(1);
				break;
			case X64_BYTE:
				operand_size = 1;
				break;
			case X64_BWORD:
				operand_size = 1 + state->size_override;
				break;
			case X64_DWORD:
				operand_size = 3;
				address_size = 3;
				break;
			case X64_PTR:
				break;
			case X64_PDESC:
				break;
			case X64_WDWORD:
				operand_size  = 3 - state->size_override + X64_MASK_REX_W(state->rex);
				break;
			case X64_WORD:
				operand_size = 2;
				break;
			case X64_QWORD:
				operand_size = 4;
				break;
			default:
				break;
		}
		state->opr_size = operand_size;
		state->addr_size = address_size;
		//Decode the addressing modes
		char reg; //May be needed 
		switch(operand[0]) {
			case X64_DIRECT_ADDRESSING:
				opr->type = X64O_REL;
				memcpy(&opr->relative, state->stream+*state->iter, 4);
				opr->relative = (int32_t)opr->relative;
				//x64_load_disp32(&opr->relative, state->stream + *state->iter);
				*state->iter += 4;
				break;
			case X64_CONTROL_REG:
				opr->type = X64O_STR;
				reg = MASK_MODRM_REG(state->stream[state->operand_start]);
				opr->operand = x86_control_registers[reg];
				break;
			case X64_DEBUG_REG:
				opr->type = X64O_STR;
				reg = MASK_MODRM_REG(state->stream[state->operand_start]);
				opr->operand = x86_debug_registers[reg];
				break;
			case X64_MODRM:
				x64_decode_modrm(opr, state);
				break;
			case X64_FLAGS_REG:
				opr->type = X64O_STR;
				opr->operand = "rflags";
				break;
			case X64_REG://Rex.b does not affect reg field
				opr->operand = x64_get_register(MASK_MODRM_REG(state->stream[state->operand_start]), state->opr_size,  X64_MASK_REX_R(state->rex));
				opr->type = X64O_STR;
				break;
			case X64_IMM:
				opr->type = X64O_IMM;
				if (state->opr_size == 4) {
					opr->immediate = *(uint64_t*)(state->stream+*state->iter);
					*state->iter += 8;
				} else if (state->opr_size == 3) {
					opr->immediate = *(uint32_t*)(state->stream+*state->iter);
					*state->iter += 4;
				} else if (state->opr_size == 2) {
					opr->immediate = *(uint16_t*)(state->stream+*state->iter);
					*state->iter += 2;
				} else {
					opr->immediate = state->stream[(*state->iter)++];
				}
				break;
			case X64_REL:
				opr->type = X64O_REL;
				opr->relative = 0;
				if (state->opr_size == 4) {
					memcpy(&opr->relative, state->stream+*state->iter, 8);
					*state->iter += 8;
				} else if (state->opr_size == 3) {
					memcpy(&opr->relative, state->stream+*state->iter, 4);
					opr->relative = (int32_t)opr->relative;
					*state->iter += 4;
				} else if (state->opr_size == 2) {
					memcpy(&opr->relative, state->stream+*state->iter, 2);
					*state->iter += 2;
				} else {
					//Casting will change things like 0xf4 into the correct signed int
					opr->relative = (int64_t)(signed char)state->stream[(*state->iter)++];
				}
				break;
			case X64_MEM://Mod/Rm but with register addressing disabled. Assuming the instruction is encoded correctly, a mod of 11 should not be encountered
				x64_decode_modrm(opr, state);
				break;
			case X64_MOFFSET://Offset from segment register.
				opr->type = X64O_MOFF;
				if (state->addr_size == 4) {
					memcpy(&opr->moffset, state->stream+*state->iter, 8);
					*state->iter += 8;
				} else if (state->addr_size == 3) {
					memcpy(&opr->moffset, state->stream+*state->iter, 4);
					opr->relative = (int32_t)opr->relative;
					*state->iter += 4;
				} else if (state->addr_size == 2) {
					memcpy(&opr->moffset, state->stream+*state->iter, 2);
					*state->iter += 2;
				} else {
					opr->moffset = state->stream[(*state->iter)++];
				}	
				break;
			case X64_MOD_REG://As far as I can tell only affects encoding (mod field of modrm byte only can refer to a general register)
				//Forced mod of 11 (register)
				state->stream[state->operand_start] |= 0xC0;
				opr->type = X64O_STR;
				x64_decode_modrm(opr, state);
				break;
			case X64_SEG_REG://Reg field of a modrm byte selects a segment register
				opr->type = X64O_STR;
				reg = MASK_MODRM_REG(state->stream[state->operand_start]);
				opr->operand = x86_segment_registers[reg];
				break;
			case X64_TEST_REG:
				opr->type = X64O_STR;
				reg = MASK_MODRM_REG(state->stream[state->operand_start]);
				opr->operand = x86_test_registers[reg];
				break;
			case X64_DSSI_MEM://ds: [esi] (esi=6)
				opr->type = X64O_INDIR;
				opr->seg_o = 1;
				opr->seg_offset = x86_segment_registers[3];//ds == 3
				opr->indirect = 1;
				opr->base = x64_get_register(6, state->addr_size, X64_MASK_REX_B(state->rex));
				break;
			case X64_ESDI_MEM://es: [edi] (edi=7)
				opr->type = X64O_INDIR;
				opr->seg_o = 1;
				opr->seg_offset = x86_segment_registers[0];//es == 1
				opr->indirect = 1;
				opr->base = x64_get_register(7, state->addr_size, X64_MASK_REX_B(state->rex));
				break;
			default:
				printf("Invalid addressing mode\n");
				exit(1);
				break;
		}
	} else {//Otherwise it is an implied or set operand (eg: eax is operand on a lot of opcodes)
		opr->operand = operand;
		int r = x_register_index(operand);
		if (r!=-1) {
			opr->operand = x64_get_register(r/4, state->opr_size,  X64_MASK_REX_B(state->rex));
			opr->type = X64O_STR;
		}
	}
	opr->size = operand_size;
	return opr;
}

void x64_decode_sib(x64_instr_operand * opr, x64_disas_state *state)
{
	char mod = MASK_MODRM_MOD(state->stream[*state->iter-1]);
	char sib_byte = state->stream[*state->iter];
	(*state->iter)++;

	int s = MASK_SIB_SCALE(sib_byte);
	switch(s) {
		case 0:
			opr->scale = 1;
			break;
		case 1:
			opr->scale = 2;
			break;
		case 2:
			opr->scale = 4;
			break;
		case 3:
			opr->scale = 8;
			break;
	}
	char index = MASK_SIB_INDEX(sib_byte);
	char base = MASK_SIB_BASE(sib_byte);
	if (index != SIB_NO_INDEX) opr->index = x64_get_register(index, state->addr_size, X64_MASK_REX_X(state->rex));
	if (!SIB_NO_BASE(mod, base)) opr->base = x64_get_register(base, state->addr_size, X64_MASK_REX_B(state->rex));

	opr->type = X64O_INDIR;
	opr->indirect = 1;
	//One byte
	if (mod == 0x1) {
		opr->disp = state->stream[(*state->iter)++];
		opr->sign = 1;
		if (opr->disp > 0x80) {
			opr->sign = 0;
			opr->disp = 0x100 - opr->disp;
		}
	} else if (mod == 0x2) {//4 byte
		memcpy(&opr->disp, state->stream + *state->iter, 4);
		(*state->iter) += 4;
		opr->sign = 1;
		if (opr->disp > 0x80000000) {
			opr->sign = 0;
			opr->disp = 0x100000000 - opr->disp;
		}
	}
	else if (mod == 0x0 && base == 0x5) {//4 byte
		memcpy(&opr->disp, state->stream + *state->iter, 4);
		(*state->iter) += 4;
		opr->sign = 1;
		if (opr->disp > 0x80000000) {
			opr->sign = 0;
			opr->disp = 0x100000000 - opr->disp;
		}
	}
}

void x64_decode_modrm(x64_instr_operand * opr, x64_disas_state *state)
{
	//Modrm byte is offset from segment if prefix states it
	opr->seg_o = state->seg_o;
	opr->seg_offset = state->seg_reg;

	char modrm = state->stream[*state->iter];
	(*state->iter)++;
	char mod = MASK_MODRM_MOD(modrm);
	char reg = MASK_MODRM_REG(modrm);
	char rm = MASK_MODRM_RM(modrm);

	if (rm == MODRM_SIB && mod != MODRM_REGISTER) {
		x64_decode_sib(opr, state);
		return;
	}
	//In 64 bit mode disponly is rip or eip relative
	if (MODRM_DISPONLY(mod, rm)) {
		opr->type = X64O_INDIR;
		//Offset from rip/eip register
		opr->base = "rip";
		opr->indirect = 1;
		opr->disp = *(uint32_t*)(state->stream+*state->iter);
		(*state->iter)+=4;
		opr->sign = 1;
		if (opr->disp > 0x80000000) {
			opr->sign = 0;
			opr->disp = 0x100000000 - opr->disp;
		}
		return;
	}
	//Indirect addressing uses address size not operand size
	switch(mod) {
		case MODRM_INDIRECT:
			opr->indirect = 1;
			opr->operand = x64_get_register(rm, state->addr_size, X64_MASK_REX_B(state->rex));
			opr->type = X64O_STR;
			break;
		case MODRM_ONEBYTE:

			opr->indirect = 1;
			opr->type = X64O_INDIR;
			opr->base = x64_get_register(rm, state->addr_size, X64_MASK_REX_B(state->rex));
			opr->index = NULL;
			opr->scale = 1;
			opr->disp = state->stream[(*state->iter)++];
			opr->sign = 1;
			if (opr->disp > 0x80) {
				opr->sign = 0;
				opr->disp = 0x100 - opr->disp;
			}
			break;
		case MODRM_FOURBYTE:
			opr->indirect = 1;
			opr->type = X64O_INDIR;
			opr->base = x64_get_register(rm, state->addr_size, X64_MASK_REX_B(state->rex));
			opr->index = NULL;
			opr->scale = 1;
			memcpy(&opr->disp, state->stream + *state->iter, 4);
			*state->iter += 4;
			opr->sign = 1;
			if (opr->disp > 0x80000000) {
				opr->sign = 0;
				opr->disp = 0x100000000 - opr->disp;
			}
			break;
		case MODRM_REGISTER:
			opr->operand = x64_get_register(rm, state->opr_size, X64_MASK_REX_B(state->rex));
			opr->type = X64O_STR;
			break;
	}
}

char *x64_sprint_operand(x64_instr_operand * opr)
{
	if (!opr) return NULL;
	char buf[256];
	memset(buf, 0, 256);
	int iter = 0;
	if (opr->indirect) {
		if (opr->size == 4) {
			iter += snprintf(buf+iter, 256-iter, "qword ");
		} else if (opr->size == 3) {
			iter += snprintf(buf+iter, 256-iter, "dword ");
		} else if (opr->size == 2) {
			iter += snprintf(buf+iter, 256-iter, "word ");
		} else iter += snprintf(buf+iter, 256-iter, "byte ");
	}
	if (opr->indirect && opr->seg_o) {
		iter += snprintf(buf+iter, 256-iter, "%s:", opr->seg_offset);
	}


	if (opr->indirect) iter += snprintf(buf+iter, 256-iter, "[");
	switch (opr->type) {
		case X64O_INDIR:
			if (opr->base) iter += snprintf(buf+iter, 256-iter, "%s", opr->base);
			if (opr->base && opr->index) iter += snprintf(buf+iter, 256-iter, "+");
			if (opr->index) iter += snprintf(buf+iter, 256-iter, "%s", opr->index);
			if (opr->index && opr->scale > 1) iter += snprintf(buf+iter, 256-iter, "*%d", opr->scale);
			if ((opr->index || opr->base) && opr->disp != 0) iter += snprintf(buf+iter, 256-iter, "%c", opr->sign ? '+' : '-');
			if (opr->disp != 0) iter += snprintf(buf+iter, 256-iter, "%#x", opr->disp);
			break;
		case X64O_REL:
			iter += snprintf(buf+iter, 256-iter, "%#lx", opr->relative);
			break;
		case X64O_IMM:
			iter += snprintf(buf+iter, 256-iter, "%#lx", opr->immediate);
			break;
		case X64O_MOFF:
			iter += snprintf(buf+iter, 256-iter, "%#lx", opr->moffset);
			break;
		case X64O_STR:
			iter += snprintf(buf+iter, 256-iter, "%s", opr->operand);
			break;
	}
	if (opr->indirect) iter += snprintf(buf+iter, 256-iter, "]");

	return strdup(buf);
}

//If their is an immediate with size of 1 byte and the other instructions are a larger size, sign extend the immediate to match
void x64_sign_extend(x64_instr_operand * op1, x64_instr_operand * op2, x64_instr_operand * op3)
{
	int max_size = 0;
	if (op1 && op1->size > max_size) max_size = op1->size;
	if (op2 && op2->size > max_size) max_size = op2->size;
	if (op3 && op3->size > max_size) max_size = op3->size;

	//Sign extend op1
	if (op1 && op1->type == X64O_IMM && op1->size < max_size) {
		if (max_size >= 3 && op1->size == 1) op1->immediate = (signed char)op1->immediate;

	}
	//Sign extend op2
	if (op2 && op2->type == X64O_IMM && op2->size < max_size) {
		if (max_size >= 3 && op2->size == 1) op2->immediate = (signed char)op2->immediate;
	}
	//Sign extend op3
	if (op3 && op3->type == X64O_IMM && op3->size < max_size) {
		if (max_size >= 3 && op3->size == 1) op3->immediate = (signed char)op3->immediate;
	}
}

uint64_t x64_resolve_address(uint64_t rel, uint64_t address, int used_bytes)
{
	address += used_bytes;
	return ((int64_t)address + (int64_t)rel);
}

void x64_disas_meta_type(r_disasm * disas)
{
	if (!disas->mnemonic) return;
	disas->metadata->type = instr_type(disas->mnemonic);
}

void x64_disas_meta_operand(r_disasm * disas, x64_instr_operand * op)
{
	if (op->type == X64O_REL) {
		r_meta_add_addr(disas->metadata, op->relative, META_ADDR_BRANCH);
	} else if (op->type == X64O_IMM && (op->size >= 3) && (op->immediate >>8 != 0) && op->immediate != 0) {
		r_meta_add_addr(disas->metadata, op->immediate, META_ADDR_DATA);
	}
}