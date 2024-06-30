
#include "syscalls_linux_amd64.h"
#include "syscalls_linux_arm64.h"

void _start() {
    syscall3(sys_write, 1, (unsigned long)(void*)"Hello World!\n", 13);
}
