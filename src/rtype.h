#ifndef _RTYPE_H
#define _RTYPE_H

#include <stdint.h>

typedef uint32_t r32addr;
typedef uint64_t r64addr;

typedef struct raddress
{
	int size;
	union {
		r32addr addr32;
		r64addr addr64;
	};
} raddress;

typedef unsigned char rbyte;

#endif