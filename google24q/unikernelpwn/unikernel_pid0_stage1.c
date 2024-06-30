static __attribute__((always_inline)) unsigned long syscall3(unsigned long n, unsigned long a1, unsigned long a2,
                                                             unsigned long a3) {
    register unsigned long r0 __asm__ ("r0") = n;
    register unsigned long r1 __asm__ ("r1") = a1;
    register unsigned long r2 __asm__ ("r2") = a2;
    register unsigned long r3 __asm__ ("r3") = a3;
    unsigned long ret;
    __asm__ __volatile__ (
        "svc 0;"
        : "+r" (r0)
        : "r" (r1), "r" (r2), "r" (r3)
        : "memory"
    );
    ret = r0;
    return ret;
}


#include "shared.h"


void _start() {

    // u_puts("pid0.1: resume pid 1 to inspect uc_struct uaf chunk");
    sys_resume(1);
    sys_pause();
    sys_write("pid0.1 trigger fptr 1", 21);



    // u_puts("pid0.1: finished | should not get here");
    while (1) {
    }
}
