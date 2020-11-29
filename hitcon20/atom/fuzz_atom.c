/*
 * This is a demo program to show how to interact with ATOMS.
 * Don't waste time on finding bugs here ;)
 *
 * Copyright (c) 2020 david942j
 */

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdint.h>
#include <stdlib.h>

// #include <linux/atoms.h>
#define ATOMS_USE_TOKEN 0x4008D900
#define ATOMS_RELEASE 55555
#define ATOMS_MEM_INFO 0x8018D901
#define ATOMS_ALLOC 0xC010D902
struct atoms_ioctl_alloc {
  size_t size;
  size_t arg2;
};

struct atoms_ioctl_meminfo {
  size_t a1;
  size_t a2;
  size_t a3;
};

#define DEV_PATH "/dev/atoms"
// #define TOKEN 0xdeadbeef
#define TOKEN 0xdea

static void child_work(int pid) {
  int fd = open(DEV_PATH, O_RDWR);
  assert(fd >= 0);
  assert(ioctl(fd, ATOMS_USE_TOKEN, TOKEN) == 0);
  // fork();
  // if (pid) {
  //   assert(ioctl(fd, ATOMS_RELEASE) == 0);
  // }
  void *ptr = mmap(0, 0x1000, PROT_READ, MAP_SHARED, fd, 0);
  assert(ptr != MAP_FAILED);
  printf("[child] Message from parent: %s\n", (char*) ptr);

  struct atoms_ioctl_meminfo meminfo;
  assert(ioctl(fd, ATOMS_MEM_INFO, &meminfo) == 0);
  printf("[child] meminfo %p %p %p\n", meminfo.a1, meminfo.a2, meminfo.a3);
  sleep(5);
  assert(ioctl(fd, ATOMS_RELEASE) == 0);
  munmap(ptr, 0x1000);
  close(fd);
}

static void parent_work() {
  int fd = open(DEV_PATH, O_RDWR);
  assert(fd >= 0);
  assert(ioctl(fd, ATOMS_USE_TOKEN, TOKEN) == 0);
  struct atoms_ioctl_alloc arg = {
    .size = 0x1000,
    .arg2 = 0xcafebabe
  };
  assert(ioctl(fd, ATOMS_ALLOC, &arg) == 0);
  void *ptr = mmap(0, 0x1000, PROT_WRITE, MAP_SHARED, fd, 0);
  assert(ptr != MAP_FAILED);
  strcpy((char*)ptr, "the secret message left by parent");
  printf("arg.arg2 %p\n", arg.arg2);

  struct atoms_ioctl_meminfo meminfo;
  assert(ioctl(fd, ATOMS_MEM_INFO, &meminfo) == 0);
  printf("[parent] meminfo %p %p %p\n", meminfo.a1, meminfo.a2, meminfo.a3);
  munmap(ptr, 0x1000);
  close(fd);
  puts("[parent] Message left.");
}

// int main(int argc, char *argv[]) {
//   if (argc == 1) {
    
//     parent_work();
//     char * newarg[] = { argv[0], "child", NULL };
//     execv(argv[0], newarg);
//   } else {
//     int pid = fork();
//     child_work(pid);
//   }
//   return 0;
// }


int main(int argc, char *argv[]) {
  int fd = open(DEV_PATH, O_RDWR);
  assert(fd >= 0);
  int tokens[3] = {0xcafe, 0xdead, 0xbeef};
  int pid = fork();
  pid = fork();
  pid = fork();
  pid = fork();
  void *ptr = NULL;
  int npages = 0;
  int tokenid = rand() % (sizeof(tokens)/sizeof(tokens[0]));
      int token = tokens[tokenid];//todo maybe random token
      int res = ioctl(fd, ATOMS_USE_TOKEN, token);
      printf("[%d] use token = %d\n", pid, res);
  while (1){
    //todo op reopen fd
    int op = rand() % 8;
    // printf("[%d] op %d\n", pid, op);
    if (op == 0) {// use token
      int tokenid = rand() % (sizeof(tokens)/sizeof(tokens[0]));
      int token = tokens[tokenid];//todo maybe random token
      int res = ioctl(fd, ATOMS_USE_TOKEN, token);
      printf("[%d] use token = %d\n", pid, res);
    } else if (op == 1) {
      npages = 1;
      struct atoms_ioctl_alloc arg = {
        .size = 0x1000 * npages,
        .arg2 = 0xcafebabe
      };
      int res = ioctl(fd, ATOMS_ALLOC, &arg);
      printf("[%d] alloc = %d %p\n", pid, res, arg.arg2);
    } else if (op == 2) {      
      ptr =  mmap(0, 0x1000, PROT_WRITE, MAP_SHARED, fd, 0);
      printf("[%d] mmap = %p\n", pid, ptr);
    } else if (op == 3) {
      if (ptr) {
        *((int*)ptr) = rand();
      }
    } else if (op == 4) {
      struct atoms_ioctl_meminfo meminfo;
      int res = ioctl(fd, ATOMS_MEM_INFO, &meminfo);
      printf("[%d] meminfo res => %p %p %p\n", pid, res, meminfo.a1, meminfo.a2, meminfo.a3);
    } else if (op == 5) {
      // munmap(ptr, 0x1000 * npages);
      // ptr = NULL;
    } else if (op == 6) {
      // close(fd);
      // fd = open(DEV_PATH, O_RDWR);
    } else if (op == 7) {
      
    }
  }
  return 0;
}
