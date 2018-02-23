#ifndef RTRIP_H
#define RTRIP_H

/*Reverset Quadruple Intermediate Representation */

typedef struct r_quad_opr {
	union {
		int temp;
		char * variable;
		long constant;
	};
	int type;
} r_quad_opr;

typedef struct r_quad {
	int oper;

	int address;
	int label;
	struct r_quad *next, *prev;
} r_quad;

r_quad * r_quad_init();
void r_quad_destroy(r_quad * quad);

#endif
