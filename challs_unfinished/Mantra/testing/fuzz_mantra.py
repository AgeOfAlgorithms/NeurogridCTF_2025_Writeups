#!/usr/bin/env python3
"""
Basic fuzzing script for Mantra challenge
Tests various inputs looking for crashes or unexpected behavior
"""
from pwn import *
import random
import string
import os
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

context.log_level = 'error'

def test_input_sequence(inputs):
    """Test a specific sequence of inputs"""
    try:
        io = process(['./glibc/ld-2.34.so', './mantra'], timeout=5)

        # Menu choice 1: Weave cord
        num_beads = inputs.get('num_beads', 100)
        io.sendlineafter(b'> ', b'1')
        io.sendlineafter(b'string: ', str(num_beads).encode())

        # Menu choice 2: Tie beads
        tie_count = inputs.get('tie_count', 3)
        io.sendlineafter(b'> ', b'2')
        io.sendlineafter(b'tie? ', str(tie_count).encode())

        for i in range(min(tie_count, num_beads)):
            bead_data = inputs.get(f'bead_{i}', 'TESTTEST')
            io.sendlineafter(b'glyphs): ', bead_data.encode())

        # Menu choice 4: Recite (read)
        recite_offset = inputs.get('recite_offset', 0)
        io.sendlineafter(b'> ', b'4')
        io.sendlineafter(b'recite? ', str(recite_offset).encode())
        io.recvuntil(b'speaks: [')
        recite_data = io.recvuntil(b']', drop=True)

        # Menu choice 3: Retie (write)
        retie_offset = inputs.get('retie_offset', 0)
        retie_data = inputs.get('retie_data', 'REPLACED')
        io.sendlineafter(b'> ', b'3')
        io.sendlineafter(b'retie? ', str(retie_offset).encode())
        io.sendlineafter(b'glyphs): ', retie_data.encode())

        # Second retie if specified
        if 'retie_offset2' in inputs:
            retie_offset2 = inputs['retie_offset2']
            retie_data2 = inputs.get('retie_data2', 'REPLACED')
            io.sendlineafter(b'> ', b'3')
            io.sendlineafter(b'retie? ', str(retie_offset2).encode())
            io.sendlineafter(b'glyphs): ', retie_data2.encode())

        io.close()
        return {'status': 'success', 'recite_data': recite_data}

    except Exception as e:
        return {'status': 'crash', 'error': str(e), 'inputs': inputs}

def fuzz_allocation_sizes():
    """Test various allocation sizes"""
    print("[+] Testing allocation sizes...")

    interesting_sizes = [
        0, 1, 2, 3, 7, 8, 15, 16,              # Small allocations
        17, 31, 32, 63, 64,                    # Powers of 2 boundaries
        96, 100, 127, 128,                     # Near tcache max
        255, 256, 511, 512,                    # Larger allocations
        1023, 1024, 2048, 4096, 10000         # Very large
    ]

    for size in interesting_sizes:
        result = test_input_sequence({
            'num_beads': size,
            'tie_count': min(3, size),
            'recite_offset': -1
        })

        if result['status'] == 'crash':
            print(f"[!] CRASH with size {size}: {result['error']}")
        else:
            chunk_size = int.from_bytes(result['recite_data'][:8], 'little')
            print(f"[+] Size {size:6d} -> chunk size: 0x{chunk_size:x}")

def fuzz_offsets():
    """Test reading/writing at various offsets"""
    print("\n[+] Testing offset ranges...")

    test_ranges = [
        # Negative offsets (heap metadata)
        (-20, 0),

        # Small positive (our array)
        (0, 200),

        # Large positive
        (1000, 1100),
        (10000, 10100),

        # Very large (might crash)
        (100000, 100100),
        (1000000, 1000100),

        # Edge cases
        (2**31 - 100, 2**31 + 100),  # Near signed int max
        (2**63 - 100, 2**63 + 100),  # Near 64-bit max
    ]

    for start, end in test_ranges:
        print(f"\n[+] Testing offsets {start} to {end}")

        for offset in range(start, end, max(1, (end - start) // 10)):
            result = test_input_sequence({
                'num_beads': 100,
                'recite_offset': offset
            })

            if result['status'] == 'crash':
                print(f"[!] CRASH at offset {offset}")
            elif result['recite_data'] and any(b != 0 for b in result['recite_data']):
                print(f"[+] Offset {offset}: non-zero data found")

def fuzz_magic_values():
    """Test writing magic values"""
    print("\n[+] Testing magic values...")

    magic_values = [
        b'HTB{FLAG}', b'FLAGXXXX', b'FLAGHERE',
        b'whispers', b'sacredxx', b'prayerxx',
        b'\xff\xff\xff\xff\xff\xff\xff\xff',  # All 0xFF
        b'\x00\x00\x00\x00\x00\x00\x00\x00',  # All 0x00
        b'\x41\x41\x41\x41\x41\x41\x41\x41',  # AAAAAAAA
    ]

    for magic in magic_values:
        result = test_input_sequence({
            'num_beads': 100,
            'recite_offset': 101,  # Top chunk size
            'retie_offset': 101,
            'retie_data': magic.decode('latin-1')
        })

        if result['status'] == 'crash':
            print(f"[!] CRASH with magic value: {magic}")
        else:
            print(f"[+] Magic {magic} OK")

def fuzz_string_formats():
    """Test different string formats for beads"""
    print("\n[+] Testing string formats...")

    test_strings = [
        'TESTTEST',                     # Standard 8 chars
        'TEST\x00\x00\x00\x00',         # With nulls
        '\x00\x00\x00\x00\x00\x00\x00\x00',  # All nulls
        '\xff\xff\xff\xff\xff\xff\xff\xff',  # All 0xFF
        '\n\n\n\n\n\n\n\n',            # Newlines
        '\\x??\\x??\\x??\\x??',        # Format string attempt
        '%s%s%s%s',                     # Format string
        '%p%p%p%p',                     # Pointer format
    ]

    for test_str in test_strings:
        try:
            result = test_input_sequence({
                'num_beads': 10,
                'bead_0': test_str,
                'recite_offset': 0
            })

            if result['status'] == 'crash':
                print(f"[!] CRASH with string: {repr(test_str)}")
            else:
                print(f"[+] String {repr(test_str)} OK")
        except:
            print(f"[!] Exception with string: {repr(test_str)}")

def parallel_fuzz():
    """Run multiple fuzzing tasks in parallel"""
    print("[+] Starting parallel fuzzing sessions...")

    # Generate random test cases
    test_cases = []

    for _ in range(1000):
        test_case = {
            'num_beads': random.choice([10, 50, 100, 200, 500]),
            'tie_count': random.randint(1, 10),
            'recite_offset': random.randint(-100, 10000),
        }

        # Add optional second write
        if random.random() < 0.5:
            test_case['retie_offset'] = random.randint(-100, 10000)
            test_case['retie_data'] = ''.join(random.choices(string.printable, k=8))

        test_cases.append(test_case)

    # Run in parallel
    crashes = 0
    interesting = 0

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(test_input_sequence, case): case
                  for case in test_cases}

        for future in as_completed(futures):
            result = future.result()

            if result['status'] == 'crash':
                crashes += 1
                print(f"[!] CRASH detected!")
                print(f"    Inputs: {result['inputs']}")
                print(f"    Error: {result['error']}")

            if result['status'] == 'success' and result.get('recite_data'):
                data = result['recite_data']
                if b'HTB{' in data or b'flag' in data.lower() or b'pray' in data.lower():
                    interesting += 1
                    print(f"[+] Interesting data found: {data}")

    print(f"\n[!] Fuzzing complete: {crashes} crashes, {interesting} interesting results")

if __name__ == '__main__':
    if len(sys.argv) > 1:
        mode = sys.argv[1]

        if mode == 'sizes':
            fuzz_allocation_sizes()
        elif mode == 'offsets':
            fuzz_offsets()
        elif mode == 'magic':
            fuzz_magic_values()
        elif mode == 'strings':
            fuzz_string_formats()
        elif mode == 'parallel':
            parallel_fuzz()
        else:
            print("Unknown mode. Use: sizes, offsets, magic, strings, parallel")
    else:
        print("Running all fuzzing tests...")
        fuzz_allocation_sizes()
        fuzz_offsets()
        fuzz_magic_values()
        fuzz_string_formats()
        parallel_fuzz()
