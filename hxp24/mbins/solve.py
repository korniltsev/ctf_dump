
from pwn import *
def extract_vm_code(f):
    e = ELF(f)
    for s in e.sections:
        if s.name == '.data':
            break
    data = s.data()
    print(hexdump(data))

extract_vm_code('./binaries/chk0.bin')