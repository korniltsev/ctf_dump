#include "defs.h"

#define __fastcall

#define _byteswap_uint64 __builtin_bswap64
#define _byteswap_ulong __builtin_bswap32

uint64 __ROL8__(uint64 v, uint8 n)
{
    asm volatile (
        " mov %2, %%cl;"
        " rol %%cl, %1;"
        : "=r"(v)
        :"r"(v), "r"(n)
        :
    );
    return v;
}

uint64 __ROR8__(uint64 v, uint8 n)
{
    asm volatile (
        " mov %2, %%cl;"
        " ror %%cl, %1;"
        : "=r"(v)
        :"r"(v), "r"(n)
        :
    );
    return v;
}
