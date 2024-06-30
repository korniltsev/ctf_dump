#include <stdio.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

int (*shellcode)();


__attribute__((always_inline)) void exec_shellcode() {
    shellcode();
}

int main(int argc, char **arg) {
    struct stat st;


    if (argc < 2) {
        printf("usage: %s <shellcode>\n", arg[0]);
        exit(1);
    }

    char *fsc = arg[1];
    printf("loading %s\n", fsc);
    int fd = open(fsc, O_RDONLY);
    if (fd == -1) {
        perror("open shellcode failed");
        exit(1);
    }

    int res = fstat(fd, &st);
    if (res == -1) {
        perror("fstat failed");
        exit(1);
    }
    int mmap_size = (st.st_size + 0xfff) & ~0xfff;


    shellcode = mmap((void *) 0xcafe000, mmap_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS,
                     -1, 0);
    printf("fptr = %p | sz  = %ld (%d) \n", shellcode, st.st_size, mmap_size);


    res = read(fd, shellcode, st.st_size);
    printf("res = %d\n", res);
    if (res != st.st_size) {
        perror("read failed");
        exit(1);
    }
    exec_shellcode();


    return 0;
}
