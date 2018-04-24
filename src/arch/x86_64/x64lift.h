#ifndef X64_LIFT_H
#define X64_LIFT_H

#include "x64assembler.h"
#include "../../dec/ril.h"

/*The Assembler shares a lot of functionality to lifting*/

ril_instruction *x64_operand_lift(char *operand);

#endif
