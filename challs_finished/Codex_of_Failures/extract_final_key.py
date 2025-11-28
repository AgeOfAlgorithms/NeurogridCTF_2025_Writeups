#!/usr/bin/env python3
"""
Generate final key and flag from v2 errno log
Author: Claude
Purpose: Extract the correct 28 errno values from child process
Created: 2025-11-22
Expected: Should produce the correct, fully printable flag
Result: (to be filled after run)
"""

# The 28 errno values captured from child process only
errnos = [2, 10, 6, 1, 2, 3, 4, 7, 6, 5, 8, 9, 2, 4, 7, 6, 10, 9, 8, 5, 6, 7, 4, 3, 2, 1, 4, 3]

print(f"Errno sequence: {errnos}")
print(f"Count: {len(errnos)}")

# Generate the key
key_chars = []
for errno in errnos:
    char = chr(errno + 0x2f)
    key_chars.append(char)

key = ''.join(key_chars)
print(f"\nGenerated key: {key}")
print(f"Key length: {len(key)}")

# Generate the flag using XOR
xor_key = bytes.fromhex("796d774b015055634677774c000358 6a4e09437c6a0541600142064f")

flag_bytes = []
for i in range(28):
    key_byte = ord(key_chars[i])
    flag_byte = key_byte ^ xor_key[i]
    flag_bytes.append(flag_byte)

flag = ''.join([chr(b) for b in flag_bytes])
print(f"\nGenerated flag: {flag}")
print(f"Flag is fully printable: {all(32 <= b <= 126 for b in flag_bytes)}")

# Show any problematic positions
problems = []
for i, b in enumerate(flag_bytes):
    if not (32 <= b <= 126):
        problems.append(f"  Position {i}: 0x{b:02x} = '{chr(b) if b < 128 else '?'}' (NON-PRINTABLE)")

if problems:
    print("\nProblematic positions:")
    for p in problems:
        print(p)
else:
    print("\n✓ All characters are printable!")
    print(f"\nFLAG: {flag}")
