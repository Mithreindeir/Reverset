#include "x86disassembler.h"

x86_instr_prefix x86_instruction_prefix(unsigned char * stream, int * len)
{
	x86_instr_prefix prefix;
	prefix.size_override = 0;
	prefix.addr_override = 0;
	prefix.segment_register = NULL;
	prefix.instr_prefix = NULL;
	prefix.extended = 0;

	int prefix_found = 0;
	do {
		prefix_found = 0;
		char c = stream[*len];
		//Check for opcode extension prefix (0F)
		if (c==0x0F) {
			prefix_found = 1;
			prefix.extended = 1;
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
			if (type == X86_ADDR_SIZE_OVERRIDE) prefix.addr_override = 1;
			if (type == X86_OPERAND_SIZE_OVERRIDE) prefix.size_override = 1;		
		}
		//Check segment override
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

r_disasm * x86_decode_instruction(unsigned char * stream, int address)
{
	int len = 0;
	x86_instr_prefix prefix = x86_instruction_prefix(stream, &len);
	unsigned char instrb = stream[len];
	len++;
	
	x86_disas_state state;
	state.addr_override = prefix.addr_override;
	state.size_override = prefix.size_override;
	state.stream = stream;
	state.iter = &len;
	state.opr_size = 3;
	state.addr_size = 3;
	state.address = address;
	state.operand_start = len;
	//Get opcode information from table
	x86_instruction instr;

	if (prefix.extended) instr = x86_instruction_extended_table[instrb];
	else instr = x86_instruction_table[instrb];

	//Check for opcode extension, and correct mnemonic
	if (!strncmp("grp", instr.mnemonic, 3)) {
		char mod = MASK_MODRM_REG(stream[len]);
		char group = instr.mnemonic[3]-0x30 - 1;
		char opr = instr.mnemonic[4];
		//Some groups all share the same operands, other differ. 'd' means use the default given by the group operand. a means use the operands in group table a and b means group table b and etc
		if (opr == 'd') {
			instr.mnemonic = x86_groups[group][mod].mnemonic;
		} else if (opr == 'a') {
			instr = x86_groups[group][mod];
		} else if (opr == 'b') {
			instr = x86_groups[group][mod+GROUP_OFFSET];
		}
	}
	x86_instr_operand* op1, *op2,* op3;
	//Decode operands
	op1 = x86_decode_operand(instr.op1, &state);
	op2 = x86_decode_operand(instr.op2, &state);
	op3 = x86_decode_operand(instr.op3, &state);
	int ub = len;
	/*Intermediate functions: Resolve relative addresses and sign extend*/
	if (op1 && op1->type == X86O_REL) op1->relative = x86_resolve_address(op1->relative,address,ub); 
	if (op2 && op2->type == X86O_REL) op2->relative = x86_resolve_address(op2->relative,address,ub); 
	if (op3 && op3->type == X86O_REL) op3->relative = x86_resolve_address(op3->relative,address,ub); 

	x86_sign_extend(op1, op2, op3);

	int iter = 0;
	char buf[32];
	if (prefix.instr_prefix) iter += snprintf(buf+iter, 32-iter, "%s ", prefix.instr_prefix);
	snprintf(buf+iter, 32-iter, "%s", instr.mnemonic);
	r_disasm * disas = r_disasm_init();
	disas->mnemonic = strdup(buf);
	x86_disas_meta_type(disas);

	if (op1) {
		x86_disas_meta_operand(disas, op1);
		disas->op[0] = x86_sprint_operand(op1);
		disas->num_operands++;

	}
	if (op2) {
		x86_disas_meta_operand(disas, op2);
		disas->op[1] = x86_sprint_operand(op2);
		disas->num_operands++;
	}
	if (op3) {
		x86_disas_meta_operand(disas, op3);
		disas->op[2] = x86_sprint_operand(op3);
		disas->num_operands++;
	}

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

x86_instr_operand *x86_decode_operand(char * operand, x86_disas_state *state)
{
	if (!operand) return NULL;
	if (strlen(operand) < 1) return NULL;

	x86_instr_operand * opr = malloc(sizeof(x86_instr_operand));
	memset(opr, 0, sizeof(x86_instr_operand));

	//32bit=3 16bit=2 8bit=1. Assume 32 bit mode
	//default size is 32 bit
	int operand_size = 3;
	int address_size = 3 - state->addr_override;

	//A capital first letter means it is an addressing mode
	if (operand[0] >= 'A' && operand[0] <= 'Z') {
		//Calculate operand and address size
		switch(operand[1]) {
			case X86_TWO_WORD:
				printf("Not implemented\n");
				//exit(1);
				break;
			case X86_BYTE:
				operand_size = 1;
				//address_size = 1; 
				break;
			case X86_BWORD:
				operand_size = 1 + state->size_override;
				//address_size = 1 + state->addr_override;
				break;
			case X86_DWORD:
				operand_size = 3;
				//address_size = 3;
				break;
			case X86_PTR:
				break;
			case X86_PDESC:
				break;
			case X86_WDWORD:
				operand_size  = 3 - state->size_override;;
				//address_size = 3 - state->addr_override;
				break;
			case X86_WORD:
				operand_size = 2;
				//address_size = 2;
				break;
			default:
				break;
		}
		state->opr_size = operand_size;
		state->addr_size = address_size;
		//Decode the addressing modes
		char reg; //May be needed 
		switch(operand[0]) {
			case X86_DIRECT_ADDRESSING:
				opr->type = X86O_REL;
				memcpy(&opr->relative, state->stream+*state->iter, 4);
				*state->iter += 4;
				break;
			case X86_CONTROL_REG:
				opr->type = X86O_STR;
				reg = MASK_MODRM_REG(state->stream[state->operand_start]);
				opr->operand = x86_control_registers[reg];
				break;
			case X86_DEBUG_REG:
				opr->type = X86O_STR;
				reg = MASK_MODRM_REG(state->stream[state->operand_start]);
				opr->operand = x86_debug_registers[reg];
				break;
			case X86_MODRM:
				x86_decode_modrm(opr, state);
				break;
			case X86_FLAGS_REG:
				opr->type = X86O_STR;
				opr->operand = "rflags";
				break;
			case X86_REG:
				opr->operand = x86_get_register(MASK_MODRM_REG(state->stream[state->operand_start]), state->opr_size);
				opr->type = X86O_STR;
				break;
			case X86_IMM:
				opr->type = X86O_IMM;
				if (state->opr_size == 3) {
					opr->immediate = *(uint32_t*)(state->stream+*state->iter);
					*state->iter += 4;
				} else if (state->opr_size == 2) {
					opr->immediate = *(uint16_t*)(state->stream+*state->iter);
					*state->iter += 2;
				} else {
					opr->immediate = state->stream[(*state->iter)++];
				}
				break;
			case X86_REL:
				opr->type = X86O_REL;
				if (state->opr_size == 3) {
					memcpy(&opr->relative, state->stream+*state->iter, 4);
					*state->iter += 4;
				} else if (state->opr_size == 2) {
					memcpy(&opr->relative, state->stream+*state->iter, 2);
					*state->iter += 2;
				} else {
					opr->relative = state->stream[(*state->iter)++];
				}
				break;
			case X86_MEM://Mod/Rm but with register addressing disabled. Assuming the instruction is encoded correctly, a mod of 11 should not be encountered
				x86_decode_modrm(opr, state);
				break;
			case X86_MOFFSET://Offset from segment register.
				opr->type = X86O_MOFF;
				if (state->addr_size == 3) {
					memcpy(&opr->moffset, state->stream+*state->iter, 4);
					*state->iter += 4;
				} else if (state->addr_size == 2) {
					memcpy(&opr->moffset, state->stream+*state->iter, 2);
					*state->iter += 2;
				} else {
					opr->moffset = state->stream[(*state->iter)++];
				}	
				break;
			case X86_MOD_REG://As far as I can tell only affects encoding (mod field of modrm byte only can refer to a general register)
				//Forced mod of 11 (register)
				state->stream[state->operand_start] |= 0xC0;
				opr->type = X86O_STR;
				x86_decode_modrm(opr, state);
				break;
			case X86_SEG_REG://Reg field of a modrm byte selects a segment register
				opr->type = X86O_STR;
				reg = MASK_MODRM_REG(state->stream[state->operand_start]);
				opr->operand = x86_segment_registers[reg];
				break;
			case X86_TEST_REG:
				opr->type = X86O_STR;
				reg = MASK_MODRM_REG(state->stream[state->operand_start]);
				opr->operand = x86_test_registers[reg];
				break;
			case X86_DSSI_MEM://ds: [esi] (esi=6)
				opr->type = X86O_INDIR;
				opr->seg_o = 1;
				opr->seg_offset = x86_segment_registers[3];//ds == 3
				opr->indirect = 1;
				opr->base = x86_get_register(6, state->addr_size);
				break;
			case X86_ESDI_MEM://es: [edi] (edi=7)
				opr->type = X86O_INDIR;
				opr->seg_o = 1;
				opr->seg_offset = x86_segment_registers[0];//es == 1
				opr->indirect = 1;
				opr->base = x86_get_register(7, state->addr_size);
				break;
			default:
				printf("Invalid addressing mode\n");
				exit(1);
				break;
		}
	} else {//Otherwise it is an implied or set operand (eg: eax is operand on a lot of opcodes)
		opr->operand = operand;
	}
	opr->size = operand_size;
	return opr;
}

void x86_decode_sib(x86_instr_operand * opr, x86_disas_state *state)
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

	if (index != SIB_NO_INDEX) opr->index = x86_get_register(index, state->opr_size);
	if (!SIB_NO_BASE(mod, base)) opr->base = x86_get_register(base, state->opr_size);

	opr->type = X86O_INDIR;
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
}

void x86_decode_modrm(x86_instr_operand * opr, x86_disas_state *state)
{
	char modrm = state->stream[*state->iter];
	(*state->iter)++;
	char mod = MASK_MODRM_MOD(modrm);
	char reg = MASK_MODRM_REG(modrm);
	char rm = MASK_MODRM_RM(modrm);

	if (rm == MODRM_SIB && mod != MODRM_REGISTER) {
		x86_decode_sib(opr, state);
		return;
	}
	//32 Displacement only mode
	if (MODRM_DISPONLY(mod, rm)) {
		opr->type = X86O_INDIR;
		//Offset from ds register
		opr->seg_o = 1;
		opr->seg_offset = x86_segment_registers[3];
		opr->indirect = 1;
		opr->disp = *(uint32_t*)(state->stream+*state->iter);
		(*state->iter)+=4;
		return;
	}
	//Indirect addressing uses address size not operand size
	switch(mod) {
		case MODRM_INDIRECT:
			opr->indirect = 1;
			opr->operand = x86_get_register(rm, state->addr_size);
			opr->type = X86O_STR;
			break;
		case MODRM_ONEBYTE:

			opr->indirect = 1;
			opr->type = X86O_INDIR;
			opr->base = x86_get_register(rm, state->addr_size);
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
			opr->type = X86O_INDIR;
			opr->base = x86_get_register(rm, state->addr_size);
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
			opr->operand = x86_get_register(rm, state->opr_size);
			opr->type = X86O_STR;
			break;
	}
}

char *x86_sprint_operand(x86_instr_operand * opr)
{
	if (!opr) return NULL;
	char buf[256];
	memset(buf, 0, 256);
	int iter = 0;
	if (opr->indirect) {
		if (opr->size == 3) {
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
		case X86O_INDIR:
			if (opr->base) iter += snprintf(buf+iter, 256-iter, "%s", opr->base);
			if (opr->base && opr->index) iter += snprintf(buf+iter, 256-iter, "+");
			if (opr->index) iter += snprintf(buf+iter, 256-iter, "%s*%d", opr->index, opr->scale);
			if (opr->index || opr->base && opr->disp != 0) iter += snprintf(buf+iter, 256-iter, "%c", opr->sign ? '+' : '-');
			if (opr->disp != 0) iter += snprintf(buf+iter, 256-iter, "%#x", opr->disp);
			break;
		case X86O_REL:
			iter += snprintf(buf+iter, 256-iter, "%#x", opr->relative);
			break;
		case X86O_IMM:
			iter += snprintf(buf+iter, 256-iter, "%#x", opr->immediate);
			break;
		case X86O_MOFF:
			iter += snprintf(buf+iter, 256-iter, "%#x", opr->moffset);
			break;
		case X86O_STR:
			iter += snprintf(buf+iter, 256-iter, "%s", opr->operand);
			break;
	}
	if (opr->indirect) iter += snprintf(buf+iter, 256-iter, "]");

	return strdup(buf);
}

//If their is an immediate with size of 1 byte and the other instructions are a larger size, sign extend the immediate to match
void x86_sign_extend(x86_instr_operand * op1, x86_instr_operand * op2, x86_instr_operand * op3)
{
	int max_size = 0;
	if (op1 && op1->size > max_size) max_size = op1->size;
	if (op2 && op2->size > max_size) max_size = op2->size;
	if (op3 && op3->size > max_size) max_size = op3->size;

	//Sign extend op1
	if (op1 && op1->type == X86O_IMM && op1->size < max_size) {
		if (max_size == 3 && op1->size == 1) op1->immediate = (signed char)op1->immediate;
	}
	//Sign extend op2
	if (op2 && op2->type == X86O_IMM && op2->size < max_size) {
		if (max_size == 3 && op2->size == 1) op2->immediate = (signed char)op2->immediate;
	}
	//Sign extend op3
	if (op3 && op3->type == X86O_IMM && op3->size < max_size) {
		if (max_size == 3 && op3->size == 1) op3->immediate = (signed char)op3->immediate;
	}
}

uint32_t x86_resolve_address(uint32_t rel, uint32_t address, int used_bytes)
{
	address += used_bytes;
	return address + rel;
}

void x86_disas_meta_type(r_disasm * disas)
{
	if (!disas->mnemonic) return;
	disas->metadata->type = instr_type(disas->mnemonic);
}

void x86_disas_meta_operand(r_disasm * disas, x86_instr_operand * op)
{
	if (op->type == X86O_REL) {
		r_meta_add_addr(disas->metadata, op->relative, META_ADDR_BRANCH);
	} else if (op->type == X86O_IMM && op->size == 3 && (op->immediate >>8 != 0) && op->immediate != 0) {
		r_meta_add_addr(disas->metadata, op->immediate, META_ADDR_DATA);
	} else if (op->type == X86O_INDIR && op->size == 3 && (op->disp >>8 != 0)) { //4 byte disp offset
		r_meta_add_addr(disas->metadata, op->disp, META_ADDR_DATA);
	} 
}