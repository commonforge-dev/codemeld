#include "textflag.h"

TEXT ·i386Getpid(SB),NOSPLIT,$0-4
	MOVL $20, AX
	INT $0x80
	MOVL AX, ret+0(FP)
	RET
