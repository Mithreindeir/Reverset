#ifndef _R_PIPE_H
#define _R_PIPE_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

typedef struct r_pipe
{
	char * buf;
	int len;
	int buf_size;

} r_pipe;

r_pipe * r_pipe_init();
void r_pipe_destroy(r_pipe * pipe);

void r_pipe_clear(r_pipe * pipe);
void r_pipe_write(r_pipe * pipe, char * format, ...);
char * r_pipe_read(r_pipe * pipe, int loc, int size);

#endif