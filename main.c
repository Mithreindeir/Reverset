#include "disas.h"
#include "parse_elf.h"
#include "json-parser/json.h"

char hex_to_char(char * str)
{
	int s = strlen(str);
	if (s % 2 == 0) {
		unsigned int h, l, c=0;
		for (int i=0;i<s;i+=2) {
			h = str[i] > '9' ? str[i] - 'A' + 10 : str[i] - '0';
			l = str[i+1] > '9' ? str[i+1] - 'A' + 10 : str[i+1] - '0';
			return (h << 4) | l&0x0F; 
			c++;
		}	
	} else {
		printf("ERROR INVALID STRING\n");
		exit(1);
	}
}

static void process_value(json_value* value, int depth);

static void process_object(json_value* value, int depth)
{
    int length, x;
    if (value == NULL) {
            return;
    }
    length = value->u.object.length;
    char opcode = 0xFF;
    for (x = 0; x < length; x++) {
            if (!strcmp( value->u.object.values[x].name, "entry")) {
            	make_instruction(value->u.object.values[x].value, opcode);
            }
            else if (!strcmp( value->u.object.values[x].name, "@value")) {
               	json_value * v = value->u.object.values[x].value;
               	if (v->type != json_string) continue;
               	opcode = hex_to_char(v->u.string.ptr);
            }
            else process_value(value->u.object.values[x].value, depth+1);
    }
}

static void process_array(json_value* value, int depth)
{
        int length, x;
        if (value == NULL) {
                return;
        }
        length = value->u.array.length;

        for (x = 0; x < length; x++) {
               process_value(value->u.array.values[x], depth);
               //printf("%s\n",  value->u.string.ptr);
              	//if (!strcmp( value->u.object.values[x].name, "entry")) {
        		//	make_instruction(value->u.array.values[x]);
              	//}
        }
}

static void process_value(json_value* value, int depth)
{
        int j;
        if (value == NULL) {
                return;
        }
        if (value->type == json_object) if (!strcmp(value->u.object.values[0].name, "two-byte")) return;
        switch (value->type) {
                case json_object:
                        process_object(value, depth+1);
                        break;
                case json_array:
                        process_array(value, depth+1);
                        break;
        }
}

enum x86_OPERAND_TYPE make_instr_operand_t(json_value * a, json_value * b)
{
	if (!strcmp(a->u.string.ptr, "E")) {
		return MRM;
	}
	if (!strcmp(a->u.string.ptr, "G")) {
		return REG;
	}
	if (!strcmp(a->u.string.ptr, "O")) {
		return MOFF;
	}
	if (!strcmp(a->u.string.ptr, "Z")) {
		return RPC;
	}
	if (!strcmp(a->u.string.ptr, "I")) {
		if (!strcmp(b->u.string.ptr, "b")) {
			return IMM8;
		}
		return IMM32;
	}
	if (!strcmp(a->u.string.ptr, "J")) {
		if (!strcmp(b->u.string.ptr, "b")) {
			return REL8;
		}
		return REL1632;
	}
	return NON;
}

void make_instr_src(json_value * value, x86_opcode * op)
{
	int len = value->u.object.length;
	if (len != 2) {
		return;
	}
	json_value * a = value->u.object.values[0].value;
	json_value * b = value->u.object.values[1].value;
	op->arg2 = make_instr_operand_t(a, b);	
}

void make_instr_dest(json_value * value, x86_opcode * op)
{
	int len = value->u.object.length;
	if (len != 2) {
		return;
	}
	json_value * a = value->u.object.values[0].value;
	json_value * b = value->u.object.values[1].value;
	op->arg1 = make_instr_operand_t(a, b);
}

void make_instr_syntax(json_value * value, x86_opcode * op)
{
    int length, x;
    if (value == NULL || value->type != json_object) {
            return;
    }
    length = value->u.object.length;
	for (x = 0; x < length; x++) { 
       	if (!strcmp( value->u.object.values[x].name, "mnem")) {

       		json_value * v = value->u.object.values[x].value;
       		if (v->type != json_string) {
       			continue;
       		}
      		op->mnemonic = strdup(v->u.string.ptr);
      		int s = strlen(op->mnemonic);
       		for (int i = 0; i < s; i++) {
       			op->mnemonic[i] = tolower(op->mnemonic[i]);
       		}
       	}
       	if (!strcmp( value->u.object.values[x].name, "dst")) {
       		json_value * v = value->u.object.values[x].value;
       		if (v->type != json_object) continue;
       		make_instr_dest(v, op);
       	}
       	if (!strcmp( value->u.object.values[x].name, "src")) {
       		json_value * v = value->u.object.values[x].value;
       		if (v->type != json_object) continue;
       		make_instr_src(v, op);
       	}
	}
}

void make_instr_entry(json_value * value, x86_opcode * op)
{
    int length, x;
    if (value == NULL || value->type != json_object) {
    	if (value->type == json_array)
    	{

    		length = value->u.array.length;
    		for (int y = 0; y < length; y++) {
    			int len = value->u.array.values[y]->u.object.length;
	        	for (x = 0; x < len; x++) {
	        	    //process_value(value->u.array.values[x], depth);
			       	if (!strcmp( value->u.array.values[y]->u.object.values[x].name, "@direction")) {
			       		json_value * v = value->u.array.values[y]->u.object.values[x].value;
			       		if (v->type == json_string) op->modrm_dir = atoi(v->u.string.ptr);
			       	}
			       	if (!strcmp( value->u.array.values[y]->u.object.values[x].name, "@op_size")) {
			       		json_value * v = value->u.array.values[y]->u.object.values[x].value;
			       		if (v->type == json_string) op->size = atoi(v->u.string.ptr);
			       	}

			       	if (!strcmp( value->u.array.values[y]->u.object.values[x].name, "syntax")) {
			       		json_value * v = value->u.array.values[y]->u.object.values[x].value;
			       		make_instr_syntax(v, op);
			       	}
	    		}
    		}
    	}
    	return;
    }
   	length = value->u.object.length;
	for (x = 0; x < length; x++) {
       	if (!strcmp( value->u.object.values[x].name, "@direction")) {
       		json_value * v = value->u.object.values[x].value;
       		if (v->type == json_string) op->modrm_dir = atoi(v->u.string.ptr);
       	}
       	if (!strcmp( value->u.object.values[x].name, "@op_size")) {
       		json_value * v = value->u.object.values[x].value;	
       		if (v->type == json_string) op->size = atoi(v->u.string.ptr);
       	}
       	if (!strcmp( value->u.object.values[x].name, "syntax")) {
       		json_value * v = value->u.object.values[x].value;
       		make_instr_syntax(v, op);
       	}
       	//process_value(value->u.object.values[x].value, depth+1);
	}
}
void print_oper(enum x86_OPERAND_TYPE type)
{
	switch (type) {
		case REG:
			printf("reg");
			break;
		case MRM:
			printf("mrm");
			break;
		case IMM8:
			printf("imm8");
			break;
		case IMM32:
			printf("imm32");
			break;
		case RPC:
			printf("rpc");
			break;
		case REL8:
			printf("rel8");
			break;
		case REL1632:
			printf("rel1632");
			break;
		case ONE:
			printf("one");
			break;
		case EAX:
			printf("eax");
			break;
		case MOFF:
			printf("moff");
			break;
		default:
			printf("non");
			break;
	}
}


static int num = 0;
void make_instruction(json_value * value, char opcode)
{
	x86_opcode op = {0x00, opcode, 0x00, 0, 0, 0, NON, NON, NON, "non"}; 

    // printf("object[%d].name = %s\n", x, value->u.object.values[x].name);
	make_instr_entry(value, &op);
	//	{0x00, 0x00, 0x00, 0, 0, 0, MRM, REG, NON, "add"},
	if (strcmp(op.mnemonic, "non") != 0) {
	    printf("%02x %s ", op.opcode, op.mnemonic);
	    print_oper(op.arg1);
	    printf(", ");
	    print_oper(op.arg2);
	    printf("\n");
	    num++;
	}
	//getchar();
       	//process_value(value->u.object.values[x].value, depth+1);

}

int json_instructions()
{
	FILE * isa = fopen("x86ref.json", "r");
	if (!isa) {
		printf("x86ref.json not found\n");
		exit(1);
	}
	fseek(isa, 0, SEEK_END);
	long fsize = ftell(isa);
	fseek(isa, 0, SEEK_SET);

	char *string = malloc(fsize + 1);
	fread(string, fsize, 1, isa);

	string[fsize] = 0;
	json_value * jv = json_parse(string, fsize);
	if (!jv) {
		printf("Unable to parse data\n");
		free(string);
		exit(1);
	}

	process_value(jv, 0);
	printf("INSTRUCTIONS %d\n", num);
	json_value_free(jv);
	free(string);
	fclose(isa);
	return 0;
}

int main(int argc, char ** argv)
{
	if (argc < 2) {
		printf("format: %s bytes\n", argv[0]);
		return 1;
	}
	int dev = 1;
	unsigned char * buffer;
	unsigned int size = 0;
	elf_file * elf;
	if (dev) {
		elf = read_elf(argv[1]);
		int section = -1;
		for (int i = 0; i < elf->num_sections; i++) {
			if (!strncmp(".text", elf->sections[i]->name, 5)) {
				section = i;
				break;
			}
		}
		if (section == -1) {
			printf("NO .text section\n");
			return 1;
		}
		buffer = elf->sections[section]->data;
		size = elf->sections[section]->size;
		printf("Section: %s\n", elf->sections[section]->name);

	} else {
		buffer = malloc(255);
		int size = strlen(argv[1]);

		if (size > 255) {
			printf("Input too long\n");
		}
		memset(buffer, 0x00, 255);
		string_to_hex(argv[1], buffer);
	}
	//printf("Instruction number %d\n", sizeof(x86_opcodes)/sizeof(x86_opcode));
	//json_instructions();
	//return 0;
	//Initial disassembly decoding
	int b = 0;
	x86_instruction ** instructions = malloc(sizeof(x86_instruction*));
	int num_instructions = 1;
	x86_instruction * ci = NULL;
	while(1) {
		ci = x86_decode_instruction(buffer + b, size);
		b += ci->used_bytes;
		instructions[num_instructions-1] = ci;
		if (b >= size) {
			break;
		}
		num_instructions++;
		instructions = realloc(instructions, num_instructions * sizeof(x86_instruction*));
	}

	//Resolving relative addresses and symbols
	int addr = elf->entry_point;
	for (int i = 0; i < num_instructions; i++) {
		ci = instructions[i];
		if (ci->op1.type == REL1632) {
			signed int boff = 0;
			if (ci->op1.rel1632 < 0) boff = ci->used_bytes;
			ci->op1.rel1632 = addr + ((signed int)ci->op1.rel1632) + boff;			
		}
		if (ci->op1.type == REL8) {
			signed int boff = 0;
			if (ci->op1.rel8 > 0) boff = ci->used_bytes;
			ci->op1.rel1632 = addr + ((signed char)ci->op1.rel8) + boff;
			ci->op1.type = REL1632;	
		}
		if (ci->op2.type == REL1632) {
			signed int boff = 0;
			if (ci->op2.rel1632 < 0) boff = ci->used_bytes;
			ci->op2.rel1632 = addr + ((signed int)ci->op2.rel1632) + boff;			
		}
		if (ci->op2.type == REL8) {
			signed int boff = 0;
			if (ci->op2.rel8 > 0) boff = ci->used_bytes;
			ci->op2.rel1632 = addr + ((signed char)ci->op2.rel8) + boff;
			ci->op2.type = REL1632;	
		}
		addr += ci->used_bytes;
	}
	formatter * format = formatter_init(elf->entry_point, instructions, num_instructions);

	//Print the final disassembly
	addr = 0;
	for (int i = 0; i < num_instructions; i++) {
		if (dev) printf("%#08x\t", addr+elf->entry_point);
		ci = instructions[i];
		addr += ci->used_bytes;
		int max_bytes = 3*8;
		for (int i = 0; i < ci->used_bytes; i++) {
			if ((max_bytes - 3) <= 0) {
				printf(".");
				break;
			}
			printf("%02x ", buffer[addr-ci->used_bytes+i]);
			max_bytes -= 3;
		}
		//Align all instructions
		while (max_bytes > 0) {
			max_bytes -= 3;
			printf("   ");
		}
		formatter_printline(format, addr+elf->entry_point - ci->used_bytes);
		print_instruction(ci);
		//if (!strcmp("non", ci->mnemonic) || !strcmp("ret", ci->mnemonic)) printf("\n");
		printf("\n");
	}
	free(instructions);
	formatter_destroy(format);
	return 0;
}
