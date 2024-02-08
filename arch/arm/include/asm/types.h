#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
#ifndef __ASM_ARM_TYPES_H
#define __ASM_ARM_TYPES_H

#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
#include <asm-generic/types.h>
#else
#include <asm-generic/int-ll64.h>

#ifndef __ASSEMBLY__

typedef unsigned short umode_t;

#endif  

#endif

#ifdef __KERNEL__

#define BITS_PER_LONG 32

#endif  

#endif
