#include "operands.h"

x86_mem x86_decode_sib(unsigned char sib_byte)
{
	x86_mem mem;
	memset(&mem, sizeof(x86_mem), 0);

	int s = MASK_SIB_SCALE(sib_byte);
	switch (s) {
		case 0:
			mem.scale = 1;
			break;
		case 1:
			mem.scale = 2;
			break;
		case 2:
			mem.scale = 4;
			break;
		case 3:
			mem.scale = 8;
			break;
		default:
			mem.scale = -1;
			break;
	}
	mem.index = MASK_SIB_INDEX(sib_byte);
	mem.base = MASK_SIB_BASE(sib_byte);

	return mem;
}

void x86_load_disp32(unsigned int * dest, unsigned char * src)
{
	//Still don't know exactly why I need to do this. Have yet to find source for why the low and high bits of displacement need to be xor'd but this is the only way it produces a correct address
	char arr[4];
	memset(arr, 4, 0);
	arr[3] = *(src+3);
	arr[2] = *(src+2);
	arr[1] = 0xff;
	arr[0] = 0xff;
	unsigned int high = *((int*)arr);
	arr[3] = 0xff;
	arr[2] = 0xff;
	arr[1] = *(src+1);
	arr[0] = *(src);
	unsigned int low = *((int*)arr);
	unsigned int d = ((high)^(low)) + 0x1;
	if ((d & 0xf0000000)) {
		d = (long)0x100000000 - d;
	} 
	*dest = d;
}

//Decodes MOD and RM field plus SIB byte and Displacement returns operand
x86_operand x86_decode_rm(unsigned char * raw_bytes, int operand_size, int extension)
{
	x86_operand operand;
	memset(&operand, sizeof(x86_operand), 0);
	//
	int offset = 0;
	unsigned char mod, rm, reg;
	mod = MASK_MODRM_MOD(*raw_bytes);
	rm = MASK_MODRM_RM(*raw_bytes);
	reg = MASK_MODRM_REG(*raw_bytes);

	//If rm is set for SIB
	int sib = (rm == RM_SIB) && !extension;
	offset += sib && (mod!=MOD_REG_ADDRESS);
	//Decode SIB byte
	x86_mem mem = x86_decode_sib(*(raw_bytes+1));
	int idx = index != NO_INDEX;
	//Displacement byte
	char disp = *(raw_bytes+offset+1);
	operand.type = MRM;
	operand.modrm.sib_byte = sib;
	//32-bit displacement-only mode is when mod == 00 and r/m == 101 or ebp
	if (!mod && rm == 0x5) {
		mod = -1;
		operand.modrm.type = DISP32_ONLY;
		x86_load_disp32(&operand.modrm.mem.disp32, raw_bytes+offset+1);
		offset += 4;
	}
	switch (mod) {
		case MOD_INDIRECT_ADDRESS:
			if (sib) {
				if (mem.base == DISP_ONLY) {
					operand.modrm.type = INDIR_DISPONLY;
					operand.modrm.mem.index = mem.index;
					operand.modrm.mem.scale = mem.scale;
					if (operand_size) {
						x86_load_disp32(&operand.modrm.mem.disp32, raw_bytes+offset+1);
						offset += 4;
					} else {
						operand.modrm.mem.disp8 = disp;
						offset+1;
					}
				} else {
					operand.modrm.type = INDIR;
					operand.modrm.mem.scale = mem.scale;
					operand.modrm.mem.index = mem.index;
					operand.modrm.mem.base = mem.base;
				}
			} else {
				if (rm == DISP_ONLY) {
					operand.modrm.type = INDIR_DISPONLY;
					operand.modrm.mem.disp8 = disp;
				} else {
					operand.modrm.reg = x86_registers[rm];
					operand.modrm.type = INDIR;
				}
			}
			break;
		case MOD_ONE_BYTE_DISPLACEMENT:
			operand.modrm.type = DISP8;
			if (sib) {
				operand.modrm.mem = mem;
				operand.modrm.mem.disp8 = disp;
			} else {
				operand.modrm.reg = x86_registers[rm];
				operand.modrm.mem.disp8 = disp;	
			}
			offset++;
			break;
		case MOD_FOUR_BYTE_DISPLACEMENT:
			operand.modrm.type = DISP32;
			if (sib) {
				operand.modrm.mem = mem;
				x86_load_disp32(&operand.modrm.mem.disp32, raw_bytes+offset+1);
			} else {
				operand.modrm.reg = x86_registers[rm];
				x86_load_disp32(&operand.modrm.mem.disp32, raw_bytes+offset+1);
			}
			offset += 4;
			break;
		case MOD_REG_ADDRESS:
			operand.modrm.type = REGM;
			operand.modrm.reg = x86_registers[rm];
			break;
	}
	operand.used_bytes = offset+1;
	return operand;
}

void print_sib(x86_mem mem, x86_modrm_type type)
{
	int idx = mem.index != NO_INDEX;
	char * indexstr = x86_registers[mem.index].regs[2];
	char * basestr = x86_registers[mem.base].regs[2];
	int scale = mem.scale;

	switch (type) {
		case INDIR_DISPONLY:
			printf("[%#x+%s*%d]", mem.disp8, indexstr, scale);
			break;
		case INDIR:
			if (idx) printf("[%c+%s*%d]", mem.disp8, indexstr, scale);
			else printf("[%s]", basestr);
			break;
		case DISP8:
			if (idx) printf("[%s+%s*%c]", basestr, indexstr, scale == 1 ? '\b' : 0x30+scale);
			else printf("[%s]", basestr);
			break;
		case DISP32:
			if (idx) printf("[%s+%s*%d]", basestr, indexstr, scale);
			else printf("[%s]", basestr);
			break;

	}
}

void print_modrm(x86_modrm_byte modrm, int size)
{
	char * rmstr = modrm.reg.regs[2-size];
	switch (modrm.type) {
		case INDIR_DISPONLY:
			printf("%#x", modrm.mem.disp8);	
			break;
		case INDIR:
			printf("[%s]", rmstr);
			break;
		case REGM:
			printf("%s", modrm.reg.regs[2-size]);
			break;
		case DISP8:
			//printf("[%s%#x]", rmstr, modrm.mem);
			printf("[%s", rmstr);
			print_hex(modrm.mem.disp8);
			printf("]");
			break;
		case DISP32:
			printf("[%s-%#x]",rmstr, modrm.mem.disp32);
			break;
		case DISP32_ONLY:
			printf("[%#x]", modrm.mem.disp32);
			break;
	}
}

void print_modrm_byte(x86_modrm_byte modrm, x86_sreg seg, int size)
{
	if (modrm.type != REGM) {
		if (size) {
			printf("word ");
		}
		else if (size) {
			printf("dword ");
		} else {
			printf("byte ");
		}
	}
	if (seg.map != 0x0) {
		printf("%s:", seg.reg);
	}
	if (modrm.sib_byte)
	{
		print_sib(modrm.mem, modrm.type);
	} else {
		print_modrm(modrm, size);
	}
}

void x86_print_operand(x86_operand opr)
{	
	x86_modrm_byte modrm;
	int size = opr.size_override + opr.operand_size;

	switch (opr.type) {
		case REG:
			printf("%s", opr.reg.regs[2-size]);
			break;
		case MRM:
			print_modrm_byte(opr.modrm, opr.override, size);
			break;
		case IMM8:
			printf("%#x", opr.imm8);
			break;
		case IMM32:
			printf("%#x", opr.imm32);
			break;
		case REL8:
			printf("%#04x", opr.rel8);
			break;
		case REL1632:
			printf("%#010x", opr.rel1632);
			break;
		case RPC:
			printf("%s", opr.rpc.regs[2-size]);
			break;

	}
}