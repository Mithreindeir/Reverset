#include "rpipe.h"

r_pipe * r_pipe_init(int size)
{
	r_pipe * rp = malloc(sizeof(r_pipe));
	rp->buf_size = size;
	rp->buf = malloc(size);
	memset(rp->buf, 0, size);
	rp->len = 0;

	return rp;
}

void r_pipe_destroy(r_pipe * pipe)
{
	if (!pipe) return;

	if (pipe->buf) free(pipe->buf);
	free(pipe);
}

void r_pipe_write(r_pipe * pipe, char * format, ...)
{
	va_list args;
	va_start(args, format);
	size_t needed = vsnprintf(NULL, 0, format, args)+1;
	va_end(args);

	if ((pipe->buf_size-pipe->len) < needed) {
		needed = needed - (pipe->buf_size-pipe->len);
		//To stop a lot of small reallocs
		if (needed < 1024) needed = 1024;
		int old_size = pipe->buf_size;
		pipe->buf_size += needed;
		if (!pipe->buf) {
			pipe->buf = malloc(pipe->buf_size);
		} else {
			pipe->buf = realloc(pipe->buf, pipe->buf_size);
		}
		memset(pipe->buf + old_size, 0, needed);
	}

	va_start(args, format);
	pipe->len += vsnprintf(pipe->buf + pipe->len, pipe->buf_size-pipe->len, format, args);
	va_end(args);
}

char * r_pipe_read(r_pipe * pipe, int loc, int size)
{
	char * buffer = malloc(size+1);
	for (int i = loc; i < pipe->len && (i-loc) < size; i++) {
		buffer[i-loc] = pipe->buf[i];
	}
	buffer[size] = 0;
	return buffer;
}

void r_pipe_clear(r_pipe * pipe)
{
	memset(pipe->buf, 0, pipe->buf_size);
	pipe->len = 0;
}