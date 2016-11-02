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
int decode_rm(unsigned char * cb, int size)
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
	switch (mod) {
		case MOD_INDIRECT_ADDRESS:
			if (sib) {
				
				if (base == DISP_ONLY) {
					printf("dword [%04x+%s*%d]", disp, indexstr, scale);
				} else {
					if (idx) printf("dword [%s+%s*%d]", basestr, indexstr, scale);
					else printf("dword [%s]", basestr);
				}
			} else {
				if (rm == DISP_ONLY) {
					printf("%04x", disp);
				} else {
					printf("dword [%s]", rmstr);
				}
			}
			break;
		case MOD_ONE_BYTE_DISPLACEMENT:
			if (sib) {
				if (*(cb + offset+1) == 0x00) {
					if (idx) printf("dword [%s+%s*%c]", basestr, indexstr, scale == 1 ? '\b' : 0x30+scale);
					else printf("dword [%s]", basestr);


				} else {
					printf("dword [");
					print_hex(disp);
					if (idx) printf("%s+%s*%d", basestr, indexstr, scale);
					else  printf("%s", basestr);

				}
			} else {
				printf("dword [%s", rmstr);
				print_hex(disp);
				printf("]");
			}
			offset++;
			break;
		case MOD_FOUR_BYTE_DISPLACEMENT:
			if (sib) {
				printf("[disp+%s+%s*%d]", basestr, indexstr, scale);
			} else {
				printf("dword [%s", rmstr);
				print_hex_long(cb+offset+1, 1);
				printf("]");
			}
			offset += 4;
			break;
		case MOD_REG_ADDRESS:
			printf("%s", rmstr);
			break;
	}
	return offset+1;
}

int decode_operands(unsigned char * cb, int dir, int size, int immediate)
{
	int b = 0;
	unsigned char reg = MASK_MODRM_REG(*cb);
	if(immediate) {
		int o = 1;
		o = decode_rm(cb, size);
		printf(", ");
		print_hex(*(cb+o));
		b += o;
		b++;
	} else {
		if (dir) {
			//RM->REG so REG, RM
			printf("%s", registers[reg].names[1+size]);
			printf(", ");
			b += decode_rm(cb, size);
		} else {
			//REG->RM so RM, REG
			b += decode_rm(cb, size);
			printf(", ");
			printf("%s", registers[reg].names[1+size]);
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
int decode_instruction(unsigned char * cb, int maxsize)
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
	printf("\t");
	printf(RESET);
	printf(GRN);
	printf("%s ", op.name);
	printf(RESET);
	printf(RED);
	if (num == 2 || op.v == 0xFF)  {
		idx += decode_operands(cb+idx, op.arg1 == REG, op.s || 1, op.arg2 == IMM);	
	} else if(num == 1) {
		if (op.arg1 == RPC) {
			printf("%s", registers[op.v - op.mor].names[1+op.s]);
		} else if(op.arg1 == REL8) {
			printfhex(cb[idx]);
			idx++;
		} else if(op.arg1 == REL1632) {
			print_hex_long(cb+idx, 0);
			idx += 3; //Should be 4, but - 1 for operand byte, since addr follow opcode
		}
	}	
	printf("\n");
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
	while(1) {
		b += decode_instruction(buffer + b, size);
		if (b >= size/2) {
			break;
		}
		printf(RESET);
	}
	printf(RESET);
	return 0;
}
