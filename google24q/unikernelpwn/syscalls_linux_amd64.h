#pragma once

#ifdef __amd64__


static __attribute__((always_inline)) unsigned long syscall0(unsigned long n) {
    unsigned long ret;
    __asm__ __volatile__("syscall"
        : "=a"(ret)
        : "a"(n)
        : "rcx", "r11", "memory");
    return ret;
}

static __attribute__((always_inline)) unsigned long syscall1(unsigned long n, unsigned long a1) {
    unsigned long ret;
    __asm__ __volatile__("syscall"
        : "=a"(ret)
        : "a"(n), "D"(a1)
        : "rcx", "r11", "memory");
    return ret;
}

static __attribute__((always_inline)) unsigned long syscall2(unsigned long n, unsigned long a1, unsigned long a2) {
    unsigned long ret;
    __asm__ __volatile__("syscall"
        : "=a"(ret)
        : "a"(n), "D"(a1), "S"(a2)
        : "rcx", "r11", "memory");
    return ret;
}

static __attribute__((always_inline)) unsigned long syscall3(unsigned long n, unsigned long a1, unsigned long a2,
                                                             unsigned long a3) {
    unsigned long ret;
    __asm__ __volatile__("syscall"
        : "=a"(ret)
        : "a"(n), "D"(a1), "S"(a2), "d"(a3)
        : "rcx", "r11", "memory");
    return ret;
}

#define sys_read 0
#define sys_write 1


#endif
