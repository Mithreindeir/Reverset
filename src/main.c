#include <stdio.h>
#include <stdlib.h>

#include "rfile.h"
#include "rdis.h"
#include "ranal.h"
#include "arch/x86/x86disassembler.h"
#include "arch/x86_64/x64assembler.h"
#include "arch/x86_64/x64disassembler.h"
#include "reverset.h"

//48 2d 38 10 60 00

int main(int argc, char ** argv)
{
	if (argc < 2) {
		printf("Usage: %s file\n", argv[0]);
		return 1;
	}
	reverset * rev = reverset_init();
	reverset_openfile(rev, argv[1]);
	reverset_sh(rev);

	reverset_destroy(rev);
	return 0;
	if (argc < 2) {
		printf("Usage: %s file\n", argv[0]);
		return 1;
	}

	r_file * file = r_openfile(argv[1]);
	r_file_find_strings(file);
	r_disassembler *  disassembler = r_disassembler_init();
	r_analyzer * anal = r_analyzer_init();
	if (disassemblers[file->arch] != NULL) {
		disassembler->disassemble =  disassemblers[file->arch];
		rsection * section = r_file_get_section(file, ".text");
		r_disassembler_pushaddr(disassembler,  section->start);
		r_disassembler_add_symbols(disassembler, file);
		r_disassemble(disassembler, file);
		r_meta_analyze(anal, disassembler, file);
	} else {
		printf("Architecture not supported\n");
		return 1;
	}
	uint64_t current_address = file->entry_point;

	uint64_t * addresses = malloc(sizeof(uint64_t));
	addresses[0] = current_address;
	int num_addresses = 1;

	int run = 1;
	while (run) {
		printf("%#lx>", current_address);
		char buf[256];
		memset(buf, 0, 256);
		fgets(buf, 256, stdin);
		//Removes trailing newline
		strtok(buf, "\n");
		int size = strlen(buf);
		int iter = 0;
		while (iter < size) {
			if (buf[iter] == ' ' || buf[iter] == '\n' || buf[iter] == '\t'){
				iter++;
				continue;
			}
			else if (buf[iter] == 'd') {
				disassembler->overwrite = 1;
				r_disassembler_pushaddr(disassembler, current_address);
				r_disassemble(disassembler, file);
				r_meta_analyze(anal, disassembler, file);
			} else if (buf[iter]=='0' && buf[iter+1] == 'x') {
				char buf2[16];
				memset(buf2, 0, 16);
				buf2[0] = '0';
				buf2[1] = 'x';
				int i = 0;
				for (i = 2; i < 9 && (iter+i) < size; i++) {
					if ((buf[iter+i] >= 0x30 && buf[iter+i] < 0x40) || (buf[iter+i] >= 'a' && buf[iter+i] <= 'f'))
						buf2[i] = buf[iter+i];
					else break;
				}
				int len = 0;
				if (r_meta_isaddr(buf2, &len)) {
					current_address = (uint64_t)strtol(buf2, NULL, 0);
					num_addresses++;
					addresses = realloc(addresses, sizeof(uint64_t) * num_addresses);
					addresses[num_addresses-1] = current_address;
				}
				iter += i-1;
			} else if (buf[iter]=='p') {
				r_meta_printall(disassembler, anal,current_address);
			} else if (buf[iter] == 'q') {
				run = 0;
				break;
			} else if (buf[iter] == 'b') {
				if (num_addresses > 1) {
					num_addresses--;
					addresses = realloc(addresses, sizeof(uint64_t) * num_addresses);
				}
				current_address = addresses[num_addresses-1];
			} else if (buf[iter] == 'a') {
				if (file->arch != r_x86_64) {
					printf("Assembling is only currently available for 64 bit programs\n");
					break;
				}
				//Assemble 
				int num_bytes = 0;
				unsigned char * bytes = x64_assemble(buf+iter+1, current_address, &num_bytes);
				if (bytes) {
					printf("%d bytes: ", num_bytes);
					for (int i = 0; i < num_bytes; i++) {
						printf("%02x ", bytes[i]);
					}
					printf("\n");
				}
				break;
			} else if (buf[iter] == 'w') {
				unsigned char byte_buf[256];

				int num_bytes = 0;
				int write = 1;
				memset(byte_buf, 0, 256);
				int i = iter+1;
				for (; i < (size-1); i+=2) {
					if (buf[i]==' ') {
						i--;
						continue;
					}
					unsigned char a = buf[i];
					a = (a >= 0x30 && a < 0x40) ? a - 0x30 : ((a <= 'f' && a >= 'a') ? (a -'a'+10) : ((a <= 'F' && a >= 'A' ? (a-'A'+10) : 0)));
					unsigned char b = 0;
					if ((i+1) < size) {
						b = buf[i+1];
					} else {
						printf("invalid bytes\n");
						write = 0;
						break;
					}
					b = (b >= 0x30 && b < 0x40) ? b - 0x30 : ((b <= 'f' && b >= 'a') ? (b -'a'+10) : ((b <= 'F' && b >= 'A' ? (b -'A'+10) : 0)));
					unsigned char f = (a<<4) + (b&0x0f);
					byte_buf[num_bytes++] = f;
				}
				for (int i = 0; i < num_bytes; i++) {
					//printf("%02x ", byte_buf[i]);
				}
				iter += i;
				if (write) {
					r_file_patch(file, current_address, byte_buf, num_bytes);
					disassembler->overwrite = 1;
					r_disassembler_pushaddr(disassembler, current_address);
					r_disassemble(disassembler, file);
					r_meta_analyze(anal, disassembler, file);
				}

			} else {
				printf("%c invalid\n", buf[iter]);
				break;
			}
			iter++;
		}
	}

	r_disassembler_destroy(disassembler);
	r_file_destroy(file);
	r_analyzer_destroy(anal);

	return 0;
}