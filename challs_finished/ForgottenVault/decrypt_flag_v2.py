#!/usr/bin/env python3
"""
Script to decrypt the flag from the binary (version 2 - correct byte order)
Author: AI
Purpose: Manually decrypt the data to see what the flag should be
Created: 2025-11-20
Updated: Fixed byte order parsing
Expected result: Decrypted flag string
"""

# Parse the hex dump correctly
hex_data = """
3d5a2d59 5d59dd59 2d58855b 255cd55a
85596559 0d58d559 55599d5b 7d5d5d5c
fd5bad5b f55a6d58 3d5add5b b55a0d5b
1d5a4559 255afd5c 0d5a8d59 9d5ae55c
355aad5b 955d155a 3d5a655b ad595d5a
e55b755a fd5aed5a
"""

# Parse as bytes and convert to 16-bit little-endian values
hex_bytes = bytes.fromhex(hex_data.replace('\n', '').replace(' ', ''))
encrypted_data = []
for i in range(0, len(hex_bytes), 2):
    val = hex_bytes[i] | (hex_bytes[i+1] << 8)
    encrypted_data.append(val)

print(f"Encrypted data ({len(encrypted_data)} entries):")
print(' '.join(f'{val:04x}' for val in encrypted_data))

def rol32(val, bits):
    """Rotate left 32-bit value (as used in the assembly)"""
    val = val & 0xffffffff
    return ((val << bits) | (val >> (32 - bits))) & 0xffffffff

def ror32(val, bits):
    """Rotate right 32-bit value (as used in the assembly)"""
    val = val & 0xffffffff
    return ((val >> bits) | (val << (32 - bits))) & 0xffffffff

# Decrypt
decrypted = encrypted_data.copy()
prev_char = 0x41  # 'A'

# The handler loops from 0x2b (43) down to 0
for i in range(43, -1, -1):
    if i >= len(decrypted):
        break

    val = decrypted[i]

    # Step 1: XOR with 0x4d4c
    val = val ^ 0x4d4c

    # Step 2: ROL 2 (on 32-bit value, but only lower 16 bits are used)
    val = rol32(val, 2)

    # Step 3: XOR with 0x4944
    val = val ^ 0x4944

    # Step 4: ROR 5 (on 32-bit value)
    val = ror32(val, 5)

    # Step 5: SUB with prev_char
    val = (val - prev_char) & 0xffffffff

    # Step 6: AND with 0xff
    val = val & 0xff

    decrypted[i] = val
    prev_char = val

# Convert to string
flag = ''.join(chr(c) if 32 <= c < 127 else f'\\x{c:02x}' for c in decrypted)
print(f"\nDecrypted flag: {flag}")

# Also show raw bytes
print(f"\nHex values: {' '.join(f'{c:02x}' for c in decrypted)}")
