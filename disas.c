#include "disas.h"

int is_seg_override(char b)
{
	if (b==0x2E) return CS;
	if (b==0x36)  return SS;
	if (b==0x3E) return DS;
	if (b==0x26) return ES;
	if (b==0x64) return FS;
	if (b==0x65) return GS;
	return 0;
		
}
void print_hex(unsigned char v)
{
	//Vo=2^N-Vn
	//-Vo+2^N=Vn
	int p = v < 0x80;
	signed char vn = !p ? 256 - v : v; 
	if (p) printf("+0x%x", vn);
	else printf("-0x%x", vn);
}

x86_opcode x86_find_opcode(unsigned char v, unsigned char next, unsigned char two_byte)
{
	for (int i = 0; i < sizeof(x86_opcodes)/sizeof(x86_opcode); i++) {
		if (two_byte != x86_opcodes[i].two_bytes) continue;
		if (!(x86_opcodes[i].opcode^v)) {
			if ((x86_opcodes[i].extended&&(x86_opcodes[i].multi_byte == MASK_MODRM_REG(next))) || !x86_opcodes[i].extended)
				return x86_opcodes[i];
		}
	}
	x86_opcode op  = {0x00, 0xFF, 0x00, 0, 0, 0, NON, NON, NON, "non"};
	return op;
}

x86_instruction * x86_decode_instruction(unsigned char * raw_bytes, int len)
{
	x86_instruction *instruction = malloc(sizeof(x86_instruction));
	memset(&instruction, sizeof(x86_instruction), 0);

	//Iterator to decode each byte in instruction
	int idx = 0;
	int size_override = 0;
	//Byte containing instruction	
	unsigned char inst_byte;
	unsigned char two_byte = 0;

	x86_sreg seg_override;
	seg_override.map = 0;
	int segment = is_seg_override(raw_bytes[idx]);
	if (segment) {
		seg_override = x86_segment_registers[segment];
		idx++;
	} 

	//Check for instruction prefix (lock, repz etc)
	instruction->prefix = NO_PREFIX;
	if (raw_bytes[idx] == LOCK) {
		instruction->prefix = LOCK;
		idx++;
	} else if (raw_bytes[idx] == REPNZ) {
		instruction->prefix = REPNZ;
		idx++;
	} else if (raw_bytes[idx] == REPZ) {
		instruction->prefix = REPZ;
		idx++;
	}

	//Operand size override - 16 bit
	if (raw_bytes[idx]==0x66) {
		size_override = 1;
		idx++;
	}
	inst_byte = raw_bytes[idx];
	//Multi-byte instruction
	if (inst_byte == 0x0f) {
		two_byte = 0x0F;
		idx++;
		inst_byte = raw_bytes[idx];
	}
	idx++;
	//Direction of operands, size of operands, immediate or not
	int dir, size, imm;
	//Decode information about the operands 
	dir = ((raw_bytes[idx])&0x02);
	size = ((raw_bytes[idx])&0x01);
	imm = ((raw_bytes[idx])&0x80);

	x86_opcode op = x86_find_opcode(inst_byte, raw_bytes[idx], two_byte);
	int operand_number = (op.arg1 != NON) + (op.arg2 != NON) + (op.arg3 != NON);
	instruction->mnemonic = op.mnemonic;
	instruction->op1.type = op.arg1;
	instruction->op2.type = op.arg2;
	instruction->operand_number = operand_number;
	instruction->used_bytes = 0;

	if (operand_number == 2 || op.opcode == 0xFF) {
		x86_decode_operands(instruction, op, raw_bytes+idx);
		idx += instruction->used_bytes;
		if (op.arg1 == RPC) {
			//Subtract "base" opcode 
			instruction->op1.rpc = x86_registers[op.opcode - op.multi_byte];
		}
		//Set the operands when opcodes have a set first operand
		if (op.arg2 == ONE) {
			instruction->op2.type = IMM8;
			instruction->op2.imm8 = 1;
		}
		if (op.arg1 == EAX) {
			instruction->op1.type = REG;
			instruction->op1.reg = x86_registers[0];
		}
		if (op.arg2 == MOFF) {
			seg_override = x86_segment_registers[DS];
			instruction->op2.type = REL1632;
			x86_load_disp32(&instruction->op2.rel1632, raw_bytes+idx);
			idx += 4;
		}
	} else if (operand_number == 1) {
		instruction->op1.size_override = 0;
		if (op.arg1 == RPC) {
			//Subtract "base" opcode
			instruction->op1.rpc = x86_registers[op.opcode - op.multi_byte];
		} else if (op.arg1 == REL8) {
			instruction->op1.rel8 = raw_bytes[idx++];
		} else if (op.arg1 == REL1632) {
			memcpy(&instruction->op1.rel1632, raw_bytes+idx, 4);
			idx += 4;
		} else if (op.arg1 == IMM8) {
			instruction->op1.imm8 = raw_bytes[idx++];
		} else if (op.arg1 == IMM32) {
			memcpy(&instruction->op1.imm32, raw_bytes+idx, 4);
			idx += 4;
		} else if (op.arg1 == MRM) {
			memset(&instruction->op1, sizeof(x86_operand), 0);
			instruction->op1 = x86_decode_rm(raw_bytes+idx, op.size || 1, op.extended);
			instruction->op1.override.map = 0;
			instruction->op1.size_override = 0;
			idx += instruction->op1.used_bytes;
		}
	}
	//Set segment register override
	if (seg_override.map != 0x0) {
		if (op.arg1 == REG && operand_number == 2 || op.arg2 == MOFF) {
			instruction->op2.override = seg_override;
		} else {
			instruction->op1.override = seg_override;
		}
	}
	//Set operand override
	if (size_override) {
		if (op.arg1 != NON) instruction->op1.size_override = 1;
		if (op.arg2 != NON) instruction->op2.size_override = 1;
	}
	instruction->used_bytes = idx;
	//Relative addresses start after the current instruction, so add used bytes
	if (op.arg1 == REL1632) {
		instruction->op1.rel1632 += idx;
	} else if (op.arg1 == REL8) {
		instruction->op2.rel8 += idx;
	}
	if (op.arg2 == REL1632) {
		instruction->op2.rel1632 += idx;
	} else if (op.arg2 == REL8) {
		instruction->op2.rel8 += idx;
	}

	return instruction;
}

void string_to_hex(char * str, unsigned char * out)
{
	int s = strlen(str);
	if (s % 2 == 0) {
		unsigned int h, l, c=0;
		for (int i=0;i<s;i+=2) {
			h = str[i] > '9' ? str[i] - 'A' + 10 : str[i] - '0';
			l = str[i+1] > '9' ? str[i+1] - 'A' + 10 : str[i+1] - '0';
			out[c] = (h << 4) | l&0x0F; 
			c++;
		}	
	} else {
		printf("ERROR INVALID STRING\n");
		exit(1);
	}
}

void x86_decode_operands(x86_instruction * instr, x86_opcode opcode, unsigned char * raw_bytes)
{
	//Operand info
	int dir = opcode.arg1 == REG;
	int size = opcode.size || 1;
	int immediate = (opcode.arg2 == IMM8) || (opcode.arg2 == IMM32);
	int rpc = opcode.arg1 == RPC;
	int extended = opcode.extended;
	int one = opcode.arg2 == ONE;
	int eax = opcode.arg1 == EAX;
	
	int used_bytes = 0;
	//Get register value
	x86_reg reg = x86_registers[MASK_MODRM_REG(raw_bytes[0])];

	//Clear the operands
	memset(&instr->op1, sizeof(x86_operand), 0);
	memset(&instr->op2, sizeof(x86_operand), 0);

	//If immediate value
	if (immediate) {
		int offset = 1;
		if (!rpc && !eax) {
			instr->op1 = x86_decode_rm(raw_bytes, size, extended);
			offset = instr->op1.used_bytes;
		} else {
			offset = 0;
		}
		if (instr->op2.type == IMM32) {
			//Copy immediate value bytes into integer in operand
			//memcpy(&instr->op2.imm32, raw_bytes+offset, 4);
			char arr[4];
			arr[3] = *(raw_bytes+offset+3);
			arr[2] = *(raw_bytes+offset+2);
			arr[1] = *(raw_bytes+offset+1);
			arr[0] = *(raw_bytes+offset+0);
			instr->op2.imm32 = *((int*)arr);
			offset += 4;
		} else {
			instr->op2.imm8 = raw_bytes[offset];
			offset++;
		}

		used_bytes += offset;
		//used_bytes++;
	} else {
		//If not immediate value then both operands are encoded with modrm
		if (dir) {
			if (!rpc && !eax) {
				instr->op1.reg = reg;
			}
			if (!one) {
				instr->op2 = x86_decode_rm(raw_bytes, size, extended);
				used_bytes += instr->op2.used_bytes;
			}
		} else {
			//Swap the order of operands
			if (!one) instr->op2.reg = reg;
			if (!rpc && !eax) {
				instr->op1 = x86_decode_rm(raw_bytes, size, extended);
				used_bytes += instr->op1.used_bytes;
			}
		}
	}
	//Sign extend immediate to match other operand
	if (size) {
		if (instr->op1.type == IMM8) {
			instr->op1.type = IMM32;
			instr->op1.imm32 = SIGN_EXTEND(instr->op1.imm8);
		}
		if (instr->op2.type == IMM8) {
			instr->op2.type = IMM32;
			instr->op2.imm32 = SIGN_EXTEND(instr->op2.imm8);
		}
	}
	instr->used_bytes += used_bytes;

	//Clear segment override
	instr->op1.override.map = 0;
	instr->op2.override.map = 0;
	//Clear size override
	instr->op1.size_override = 0;
	instr->op2.size_override = 0;
	//Set size
	instr->op1.operand_size = size;
	instr->op2.operand_size = size;
}

void print_instruction(x86_instruction * instr)
{
	printf(RESET);
	printf(RED);
	
	switch (instr->prefix) {
		case LOCK:
			printf("lock ");
			break;
		case REPNZ:
			printf("repnz ");
			break;
		case REPZ:
			printf("repz ");
			break;
		default: break;
	}

	printf("%s ", instr->mnemonic);
	printf(RESET);
	printf(GRN);
	if (instr->operand_number == 1) {
		x86_print_operand(instr->op1);
	} else if (instr->operand_number == 2) {
		x86_print_operand(instr->op1);
		printf(", ");
		x86_print_operand(instr->op2);
	}
}