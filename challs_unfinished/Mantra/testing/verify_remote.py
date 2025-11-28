#!/usr/bin/env python3
"""
Quick verification that remote instance is working
Usage: python verify_remote.py
"""
from pwn import *

context.log_level = 'info'

def test_basic():
    io = remote('154.57.164.75', 30444, timeout=10)

    # Weave cord
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'string: ', b'100')
    print("✓ Cord woven")

    # Tie beads
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'tie? ', b'1')
    io.sendlineafter(b'glyphs): ', b'TESTTEST')
    print("✓ Beads tied")

    # Recite offset -1 (chunk metadata)
    io.sendlineafter(b'> ', b'4')
    io.sendlineafter(b'recite? ', b'-1')
    io.recvuntil(b'speaks: [')
    data = io.recvuntil(b']', drop=True)
    print(f"✓ Read offset -1: {data.hex()}")

    io.close()
    print("\n✅ Remote instance is working!")

if __name__ == '__main__':
    test_basic()
