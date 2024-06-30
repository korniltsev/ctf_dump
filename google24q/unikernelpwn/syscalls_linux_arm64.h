#pragma once

#ifdef __aarch64__

static __attribute__((always_inline)) unsigned long syscall3(unsigned long n, unsigned long a1, unsigned long a2,
                                                             unsigned long a3) {
    register unsigned long x0 __asm__ ("x0") = a1;
    register unsigned long x1 __asm__ ("x1") = a2;
    register unsigned long x2 __asm__ ("x2") = a3;
    register unsigned long x8 __asm__ ("x8") = n;
    unsigned long ret;
    __asm__ __volatile__ (
        "svc 0;"
        : "+r" (x0)
        : "r" (x1), "r" (x2), "r" (x8)
        : "memory"
    );
    ret = x0;
    return ret;
}

static __attribute__((always_inline)) unsigned long syscall2(unsigned long n, unsigned long a1, unsigned long a2) {
    register unsigned long x0 __asm__ ("x0") = a1;
    register unsigned long x1 __asm__ ("x1") = a2;
    register unsigned long x8 __asm__ ("x8") = n;
    unsigned long ret;
    __asm__ __volatile__ (
        "svc 0;"
        : "+r" (x0)
        : "r" (x1), "r" (x8)
        : "memory"
    );
    ret = x0;
    return ret;
}


// 63	read	man/ cs/	0x3f	unsigned int fd	char *buf	size_t count	-	-	-
// 64	write	man/ cs/	0x40	unsigned int fd	const char *buf	size_t count	-	-	-


#define sys_read 63
#define sys_write 64


#endif