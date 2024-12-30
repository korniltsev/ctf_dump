import sys
from Crypto.Cipher import AES

if len(sys.argv) != 2:
    print("usage: decrypt_flag <key>")
    sys.exit(1)

key = bytes.fromhex(sys.argv[1])
assert(len(key) == 0x10)

with open("flag.txt.enc", "rb") as f:
    nonce = f.read(0xc)
    tag = f.read(0x10)
    data = f.read()

ctx = AES.new(key, AES.MODE_GCM, nonce)
try:
    plain = ctx.decrypt_and_verify(data, tag)
    print(f"flag: {plain.decode()}")
except:
    print("Unable to decrypt the flag. You didn't get the right key!")