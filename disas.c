#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "opcodes.h"
#include "disas.h"
#include "colors.h"

const reg registers[8] = {
	{0x00, "al", "ax", "eax" },
	{0x01, "cl", "cx", "ecx" },
	{0x02, "dl", "dx", "edx" },
	{0x03, "bl", "bx", "ebx" },
	{0x04, "ah", "sp", "esp" },
	{0x05, "ch", "bp", "ebp" },
	{0x06, "sh", "si", "esi" },
	{0x07, "bh", "di", "edi" }
};

int is_prefix(char b)
{
	if (b==0xF0) {

	} else if (b==0xF2) {

	} else if (b==0xF3) {

	}
	return 0;
}
int is_address_size(char b)
{
	return 0;
}

int is_operand_size(char b)
{
	return 0;
}

int is_seg_override(char b)
{
	// 2e = cs 36 = ss 3e = ds 26 = es 64 = fs 65 = gs
	if (b==0x2E) return CS;
	if (b==0x36)  return SS;
	if (b==0x3E) return DS;
	if (b==0x26) return ES;
	if (b==0x64) return FS;
	if (b==0x65) return GS;
	return 0;
		
}

void decode_sib(unsigned char b, unsigned char * index, unsigned char * base, int * scale)
{
	int s = MASK_SIB_SCALE(b);
	switch (s) {
		case 0:
			*scale = 1;
			break;
		case 1:
			*scale = 2;
			break;
		case 2:
			*scale = 4;
			break;
		case 3:
			*scale = 8;
			break;
		default:
			*scale = 1;
			break;
	}
	*index = MASK_SIB_INDEX(b);
	*base = MASK_SIB_BASE(b);
}
void print_hex_long(unsigned char * v, int  sign)
{
	//Vo=2^N-Vn
	//-Vo+2^N=Vn
	unsigned long v1, v2, v3, v4;
	v1 = v[0];
	v2 = v[1];
	v3 = v[2];
	v4 = v[3];

	unsigned long vo = (v1 << 24) + (v2 <<16) + (v3<<8) + (v4);
	int p = vo < 0x80000000;
	signed long vn = !p ? (2*2*2*2*2*2*2*2) - vo : vo; 
	char b = sign ? (p ? '+' : '-' ) : ' '; 
	if (p) printf("%c0x%08x", b, vn);
	else printf("%c0x%08x", b, vn);
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
void printfhex(unsigned char v)
{
	unsigned char h, l;
	h = (v & 0xF0) >> 4;
	l = v & 0x0F;
	if (h <= 9) h += '0';
	else h = (h + 'a') - 10;
	if (l <= 9) l += '0';
	else l = (l + 'a') - 10;

	printf("%c%c", h,l);
}

//Decodes MOD and RM field plus SIB byte and Displacement, returns total bytes used
int decode_rm(operand * opr, unsigned char * cb, int size)
{
	int offset = 0;
	unsigned char mod, rm;
	mod = MASK_MODRM_MOD(*cb);
	rm = MASK_MODRM_RM(*cb);

	unsigned char index, base;
	int scale;
	int sib = rm == RM_SIB;
	offset += sib && (mod!=MOD_REG_ADDRESS);
	decode_sib(*(cb+1), &index, &base, &scale);
	int idx = index != NO_INDEX;
	char * indexstr = registers[index].names[1+size];
	char * basestr = registers[base].names[1+size];
	char * rmstr = registers[rm].names[1+size];
	char disp = *(cb+offset+1);
	opr->operand_t = mrm;
	opr->mrm.is_sib = sib;
	switch (mod) {
		case MOD_INDIRECT_ADDRESS:
			
			if (sib) {
				
				if (base == DISP_ONLY) {
					opr->mrm.mt = indir_disponly;
					opr->mrm.sib.index = index;
					opr->mrm.sib.scale = scale;
					opr->mrm.disp8 = disp;
				} else {
					opr->mrm.mt = indir;
				}
			} else {
				if (rm == DISP_ONLY) {
					opr->mrm.mt = indir_disponly;
					opr->mrm.disp8 = disp;
				} else {
					opr->mrm.regr = rm;
					opr->mrm.mt = indir;
				}
			}
			break;
		case MOD_ONE_BYTE_DISPLACEMENT:
			opr->mrm.mt = disp8;
			if (sib) {
				opr->mrm.sib.scale = scale;
				opr->mrm.sib.index = index;
				opr->mrm.sib.base = base;

			} else {
				opr->mrm.regr = rm;
				opr->mrm.disp8 = disp;	
			}
			offset++;
			break;
		case MOD_FOUR_BYTE_DISPLACEMENT:
			opr->mrm.mt = disp32;
			if (sib) {
				opr->mrm.sib.scale = scale;
				opr->mrm.sib.index = index;
				opr->mrm.sib.base = base;
			} else {
				opr->mrm.regr = rm;
				memcpy(opr->mrm.disp32, cb+offset+1, 4);
			}
			offset += 4;
			break;
		case MOD_REG_ADDRESS:
			opr->mrm.mt = regm;
			opr->mrm.regr = rm;
			break;
	}
	return offset+1;
}

int decode_operands(instruction * instr, unsigned char * cb, int dir, int size, int immediate, int rpc)
{
	int b = 0;
	unsigned char reg = MASK_MODRM_REG(*cb);
	if(immediate) {
		int o = 1;
		if (!rpc) o = decode_rm(&instr->op1, cb, size);
		else o = 0;
		if (instr->op2.operand_t == imm32) {
			//Assumes little endian
			instr->op2.imm32[3] = *(cb+o);
			instr->op2.imm32[2] = *(cb+o+1);
			instr->op2.imm32[1] = *(cb+o+2);
			instr->op2.imm32[0] = *(cb+o+3);
			b += 3;
		} else {
			instr->op2.imm8 = *(cb+o);
		}
		b += o;
		b++;
	} else {
		if (dir) {
			//RM->REG so REG, RM
			if (!rpc) instr->op1.regr = reg;
			b += decode_rm(&instr->op2, cb, size);
		} else {
			//REG->RM so RM, REG
			if (!rpc) b += decode_rm(&instr->op1, cb, size);
			instr->op2.regr = reg;
		}
	}
	return b;
}

opcode find_opcode(unsigned char v, unsigned char next)
{
	for (int i = 0; i < sizeof(opcodes)/sizeof(opcode); i++) {
		if (!(opcodes[i].v^v)) {
			if ((opcodes[i].e&&(opcodes[i].mor == MASK_MODRM_REG(next))) || !opcodes[i].e)
				return opcodes[i];
		}
	}
		opcode op  = {0xFF, 0x00, 0, 0, 0, NON, NON, NON, "non"};
		return op;
}

int decode_instruction(instruction * instr, unsigned char * cb, int maxsize)
{
	printf(RESET);
	printf(CYN);
	int idx = 0;
	unsigned char cmd;
	if (is_prefix(cb[idx])) {
		printfhex(cb[idx]);
		idx++;
	}
	if (is_address_size(cb[idx])) {
		printfhex(cb[idx]);
		idx++;
	}
	int f32 = is_operand_size(cb[idx]);
	if (f32) {
		printfhex(cb[idx]);
	       	idx++;
	}
	int seg = is_seg_override(cb[idx]);
	if (seg) {
		printfhex(cb[idx]);
		idx++;
	}
	cmd = cb[idx];
	if (cmd == 0x0f) {
		printfhex( cb[idx]);
		idx++;
		cmd = cb[idx];
	}
	printfhex(cb[idx]);
	idx++;
	int dir, size, imm;
	dir = ((cb[idx])&0x02);
	size = ((cb[idx]&0x1));
	imm = ((*cb)&0x80);
	opcode op = find_opcode(cmd, cb[idx]);
	int num = (op.arg1 != NON) + (op.arg2 != NON) + (op.arg3 != NON);
	if (op.arg1 == MRM || op.arg1 == REG) for (int i = 0; i < num; i++) printfhex(cb[idx+i]);
	else if (op.arg1 == REL8) printfhex(cb[idx+1]);
	else if (op.arg1 == REL1632) print_hex_long(cb+idx, 0); 
	printf(RESET);
	printf("\t");
	instr->instr = op.name;
	instr->op1.operand_t = op.arg1;
	instr->op2.operand_t = op.arg2;
	instr->num_ops = num;
	if (num == 2 || op.v == 0xFF)  {
		idx += decode_operands(instr, cb+idx, op.arg1 == REG, op.s || 1, (op.arg2 == IMM8 || op.arg2 == IMM32), op.arg1 == RPC);
		if (op.arg1 == RPC) {
			instr->op1.rpc = op.v - op.mor;
		}
	} else if(num == 1) {
		if (op.arg1 == RPC) {
			instr->op1.rpc = op.v - op.mor;
		} else if(op.arg1 == REL8) {
			instr->op1.imm8 = cb[idx];
			idx++;
		} else if(op.arg1 == REL1632) {
			memcpy(instr->op1.rel1632, cb+idx, 4);
			idx += 3; //Should be 4, but - 1 for operand byte, since addr follow opcode
		}
	}	
	return idx;
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

void print_operand(operand opr)
{

	switch (opr.operand_t) {
		case regr:
			printf("%s", registers[opr.regr].names[2]);
			break;
		case mrm:
			;//Empty statement for weird gcc error (no declarations after labels)
			mrm_byte m = opr.mrm;
			int idx = m.sib.index != NO_INDEX;
			char * indexstr = registers[m.sib.index].names[2];;
			char * basestr = registers[m.sib.base].names[2];
			char * rmstr = registers[m.regr].names[2];
			int scale = m.sib.scale;
			switch (m.mt) {
				case indir_disponly:
					if (m.is_sib) {
						printf("dword [%04x+%s*%d]", m.disp8, indexstr, scale);
					} else {
						printf("%04x", m.disp8);		
					}
					break;
				case indir:
					if (m.is_sib) {
						if (idx) printf("dword[%s+%s*%d]", m.disp8, indexstr, scale);
						else printf("dword [%s]", basestr);
					} else {
						printf("%s", rmstr);
					}
					break;
				case regm:
					printf("%s", registers[m.regr].names[2]);
					break;
				case disp8:
					if (m.is_sib) {
						if (m.disp8 == 0) {
							if (idx) printf("dword [%s+%s*%c]", basestr, indexstr, scale == 1 ? '\b' : 0x30+scale);
							else printf("dword [%s]", basestr);
						} else {
							printf("dword [");
							print_hex(m.disp8);
							if (idx) printf("%s+%s*%d", basestr, indexstr, scale);
							else  printf("%s", basestr);	
						}

					} else {
						printf("dword [%s", rmstr);
						print_hex(m.disp8);
						printf("]");
					}
					break;
				case disp32:
					if (m.is_sib) {
						printf("[disp+%s+%s*%d]", basestr, indexstr, scale);
					} else {
						printf("dword [%s", rmstr);
						print_hex_long(m.disp32, 1);
						printf("]");
					}
					break;
			}
			break;
		case imm8:
			printf("%d", opr.imm8);
			break;
		case imm32:
			printf("0x");
			int front = 1;
			for (int i = 0; i < 4; i++) {
				if (opr.imm32[i] == 0 && front && i < 3) continue;
				printf("%02x", opr.imm32[i]);
				front = 0;
			}
			break;
		case rel8:
			printfhex(rel8);
			break;
		case rel1632:

			break;
		case rpc:
			printf("%s", registers[opr.rpc].names[2]);
			break;

	}
}

action find_action(char * name)
{
	int i = 0;
	for (i = 0; i < (sizeof(actions)/sizeof(action)); i++) {
		if (!strcmp(name, actions[i].name)) return actions[i];
	}
	return actions[i];
}

void print_instruction(instruction * instr)
{
	printf(RESET);
	printf(RED);
	printf("%s ", instr->instr);
	printf(RESET);
	printf(GRN);
	if (instr->num_ops == 1) {
		print_operand(instr->op1);
	} else if (instr->num_ops == 2) {
		print_operand(instr->op1);
		printf(", ");
		print_operand(instr->op2);
	}
	instr->inst_action = find_action(instr->instr);
	return;
	printf(RESET);
	printf(MAG);	
	printf("\r\t\t\t\t\t; ");
	if (instr->num_ops == 2) {
		print_operand(instr->op1);
		action a;
		a = find_action(instr->instr);
		instr->inst_action = a;
		printf(" %s ", a.symbol);
		print_operand(instr->op2);
	
	}
}

void init_dec_instructions(dec_instruction * d_instrs, int num_dinstrs, instruction * instructions)
{
	dec_instruction d_ci;
	char * var = "local0";
	for (int i = 0; i < num_dinstrs; i++) {
		
		//var->reg first
		instruction * ci = &instructions[i];
		d_ci.instr = *ci;
		d_ci.doprn.dact = ci->inst_action;
		d_ci.first = 1;
		d_ci.exclusive = 1;
		d_ci.invalid = 0;

		if (ci->num_ops != 2) continue;

		d_ci.doprn.num_ops = 2;
		d_ci.doprn.dopr1.type = 1;
		d_ci.doprn.dopr1.undeter.opr = ci->op1;
		d_ci.doprn.dopr1.next = NULL;

		d_ci.doprn.dopr2.type = 1;
		d_ci.doprn.dopr2.undeter.opr = ci->op2;
		d_ci.doprn.dopr2.next = NULL;

		if (ci->op1.operand_t == mrm) {
			if (ci->op1.mrm.regr == 5 && ci->op1.mrm.mt == 3) {
				d_ci.doprn.dopr1.type = 0;
				d_ci.doprn.dopr1.local.offset = TWO_COMPLEMENT(ci->op1.mrm.disp8);
			}
		}
		if (ci->op2.operand_t == mrm) {
			if (ci->op2.mrm.regr == 5 && ci->op2.mrm.mt == 3) {
				d_ci.doprn.dopr2.type = 0;
				d_ci.doprn.dopr2.local.offset = TWO_COMPLEMENT(ci->op2.mrm.disp8);
			}
		}
		d_instrs[i] = d_ci;
	}

}

int operands_equal(operand op1, operand op2)
{
	return 0;
}


int dec_operands_equal(dec_operand d1, dec_operand d2)
{

	//In context, you only need to compare the undeter if its a register
	if (d1.type != d2.type) return 0;
	
	if (d1.type == 0 && d2.local.offset == d1.local.offset)
		return 1;
	else if (d1.type == 1) {
		int d1reg = d1.undeter.opr.operand_t == regr;
	       	int d1mrm = d1.undeter.opr.mrm.mt == regm;

		int d2reg = d2.undeter.opr.operand_t == regr;
	       	int d2mrm = d2.undeter.opr.mrm.mt == regm;
		
		if (d1reg && d2reg) {
			if (d2.undeter.opr.regr == d1.undeter.opr.regr)
				return 1;
		} else if (d1mrm && d2mrm) {
			if (d2.undeter.opr.mrm.regr == d1.undeter.opr.mrm.regr)
				return 1;
		} else if (d1reg && d2mrm) {
			if (d1.undeter.opr.regr == d2.undeter.opr.mrm.regr)
				return 1;
		} else if (d1mrm && d2reg) {
			if (d1.undeter.opr.mrm.regr == d2.undeter.opr.regr) 
				return 1;
		}
		return 0;
	}
	return 0;
}

int find_usage_assignment_op1(dec_instruction * d_instrs, int num_dinstrs, int idx, dec_operand d_op)
{
	for (int i = idx; i < num_dinstrs; i++) {
		dec_instruction c_dci = d_instrs[i];
		if (c_dci.doprn.num_ops == 2 && (c_dci.instr.inst_action.op_action == ASN)) {
			if (dec_operands_equal(c_dci.doprn.dopr1, d_op))
				return i;
		}
	}
	return -1;
}

int find_usage_assignment_op2(dec_instruction * d_instrs, int num_dinstrs, int idx, dec_operand d_op)
{
	for (int i = idx; i < num_dinstrs; i++) {
		dec_instruction c_dci = d_instrs[i];
		if (c_dci.doprn.num_ops == 2 && (c_dci.instr.inst_action.op_action == ASN)) {
			if (dec_operands_equal(c_dci.doprn.dopr2, d_op))
				return i;
		}
	}
	return -1;
}

void print_dec_instructions(dec_instruction * d_instrs, int num_dinstr)
{
	printf(RESET);
	printf(MAG);	
	printf("\n");
	dec_instruction d_ci;
	for (int i = 0; i < num_dinstr; i++) {
		d_ci = d_instrs[i];
		
		if (d_ci.instr.num_ops == 2) {
			printf(RESET);
			printf(MAG);
			if (d_ci.invalid) {
				continue;
			}
			
			if (d_ci.doprn.dopr1.type) {
				print_operand(d_ci.doprn.dopr1.undeter.opr);
			} else {
				printf("local%d", d_ci.doprn.dopr1.local.offset);
			}
			
			printf(" %s ", d_ci.doprn.dact.symbol);
				
			if (d_ci.doprn.dopr2.type) {
				print_operand(d_ci.doprn.dopr2.undeter.opr);
			} else {
				printf("local%d", d_ci.doprn.dopr2.local.offset);
			}
			int i = 5;
			
			dec_operand d_n = d_ci.doprn.dopr2;
			if (d_ci.doprn.dopr2.next) {
				while (d_n.next) {
					printf(" %s ", d_n.opr_action.symbol_indir);
					
					if (d_n.next->type) {
						print_operand(d_n.next->undeter.opr);
					} else {
						printf("local%d", d_n.next->local.offset);
					}
					
					d_n = *d_n.next;
				}
			}
		}
		printf("\n");
	}
	printf(RESET);
}

void decompile(instruction * instructions, int num_instructions)
{
	//S0 Operation decoding (done)
	//S1 Operand Aliasing
	//S2 Type inference, and variable replacing
	//S3 redundancy removal
	
	
	/*	
	for (int i = 0; i < num_instructions; i++) {
		instruction instr = instructions[i];
		printf(RESET);
		printf(MAG);	
		printf("; ");
			
		if (instr.num_ops == 2) {
			print_operand(instr.op1);
			printf(" %s ", instr.inst_action.symbol);
			print_operand(instr.op2);
		}
		printf("\n");
	}
	*/


	printf("\n");
	//At this point it becomes invalid assembly (technically)

	//S2
	//Find creation of a variable
	//Trace all instances of it backwards
	//Places where a register is set to it, it is an indirect reference
	//example: Tracing variable "var1", instruction = "mov eax, dword [ebp-4]"
	//This may be used for something like "var2 = var1 + 5;"
	//However, if the register is transfered back to the variable, it is directly being used
	//"mov dword [ebp-4], eax"
	//Find transfer from reg->var for direct
	//Find transfer from var->reg for indirect
	
	//Stack first
	//First replace all instructions with displacements to ebp
	//with variable
	dec_instruction * d_instrs = malloc(num_instructions * sizeof(dec_instruction));
	dec_instruction d_ci;
	int num_dinstr = num_instructions;

	init_dec_instructions(d_instrs, num_dinstr, instructions);
	print_dec_instructions(d_instrs, num_dinstr);
	//Find assignment to register
	//Then find when register is not the 
	//first operand, and work backwards to find
	//usage of it
	/*
	 * local4 = 5
	 * eax = local4
	 * eax += 2
	 * local8 = eax
	 * Then it goes to
	 * local 4 = 5
	 * local8 = local4 + 2
	 */
	
	int using_local = 0; //current register
	int using_reg = 0; //current offset var

	dec_operand current_local;
	dec_operand current_reg;

	int last_instr = 0;
	for (int i = 0; i < num_dinstr; i++) {
		d_ci = d_instrs[i];
		
		if (d_ci.instr.num_ops == 2) {
			if (!using_local) {
				int t1, t2;
				t1 = d_ci.doprn.dopr1.type;
				t2 = d_ci.doprn.dopr2.type;
				if (t1^t2) {
					last_instr = i;
					using_local = 1;
					if (!t1) {
						current_local = d_ci.doprn.dopr1;
					} else {
						current_local = d_ci.doprn.dopr2;
					}
				} else {
					continue;
				}
			} else {
				//Find which operand is coff
				int op; //0 or 1
				if (dec_operands_equal(d_ci.doprn.dopr1, current_local)) {
					op = 0;
				} else if (dec_operands_equal(d_ci.doprn.dopr2, current_local)) {
					op = 1;
				} else {
					continue;
				}
				if (!using_reg) {
					
					if (op) {
						if (d_ci.doprn.dopr1.type) {

							if (d_ci.doprn.dopr1.undeter.opr.operand_t == regr || d_ci.doprn.dopr1.undeter.opr.mrm.mt == regm) {
								using_reg = 1;
								current_reg = d_ci.doprn.dopr1;
							}
						}		
					} else {
						if (d_ci.doprn.dopr2.type) {

							if (d_ci.doprn.dopr2.undeter.opr.operand_t == regr || d_ci.doprn.dopr2.undeter.opr.mrm.mt == regm) {
								using_reg = 1;
								current_reg = d_ci.doprn.dopr2;
							}
						}		
					}

					if (!using_reg) continue;
				}
				if (d_ci.instr.inst_action.op_action != ASN && dec_operands_equal(d_ci.doprn.dopr1, current_reg))
					continue;
				int nidx = i;
				while (nidx < num_dinstr) {
					int first_assn = find_usage_assignment_op2(d_instrs, num_dinstr, nidx, current_reg);
					dec_instruction * d_cng = &d_instrs[first_assn];
					if (first_assn == -1)
						break;
					int j = 0;

					d_cng->doprn.dopr2 = current_local;
					d_cng->doprn.dopr2.first = 1;
					d_cng->doprn.dopr2.next = NULL;					
					dec_operand * c_op = &d_cng->doprn.dopr2;
					
					d_instrs[nidx].invalid = 1;
					for (j = nidx+1; j < first_assn; j++) {
						dec_instruction d_ci2 = d_instrs[j];

						if (!dec_operands_equal(current_reg, d_ci2.doprn.dopr1)) {
							continue;	
						}
						d_instrs[j].invalid = 1;
						if (dec_operands_equal(current_reg, d_ci2.doprn.dopr2)) {
							d_instrs[j].doprn.dopr2 = current_local;									}
						c_op->next = &d_instrs[j].doprn.dopr2;
						c_op->opr_action = d_ci2.doprn.dact;
						c_op = c_op->next;
						
							
					}
	
					nidx = j+1;
				}
				using_local = 0;
				using_reg = 0;
			}


		}
	}

	print_dec_instructions(d_instrs, num_dinstr);
}
	


int main(int argc, char ** argv)
{
	if (argc < 2) {
		printf("format: %s bytes\n", argv[0]);
		return 1;
	}
	unsigned char buffer[256];
	int size = strlen(argv[1]);
	if (size > 255) {
		printf("Input too long\n");
	}
	memset(buffer, 0x00, 255);
	string_to_hex(argv[1], buffer);
	int b = 0;
	instruction * instructions = malloc(sizeof(instruction));
	int num_instructions = 1;
	instruction ci;
	while(1) {
		
		b += decode_instruction(&ci, buffer + b, size);
		print_instruction(&ci);
		printf("\n");
		
		instructions[num_instructions-1] = ci;
		num_instructions++;
		instructions = realloc(instructions, num_instructions * sizeof(instruction));
		if (b >= size/2) {
			break;
		}
		printf(RESET);
	}
	decompile(instructions, num_instructions);
	printf("\n");
	printf(RESET);
	return 0;
}
