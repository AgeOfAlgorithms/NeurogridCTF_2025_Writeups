#!/usr/bin/env python3
"""
Search for Guardian Auth Tokens in PGP Data
Try multiple transformation methods
"""

import re

# Read corrupted data
with open('/home/sean/ctf/NeurogridCTF_2025/Ink Vaults/pgp_extraction/scroll7_pgp_key.bin', 'rb') as f:
    data = f.read()

print(f"Data size: {len(data)} bytes\n")

# Try different XOR keys
xor_keys = [
    (0x07, "Bell character (0x07)"),
    (0x30, "Character '0'"),
    (0x37, "Character '7'"),
    (0xe9, "First byte of 靑 UTF-8"),
    (0x9d, "Second byte of 靑 UTF-8"),
    (0x91, "Third byte of 靑 UTF-8"),
]

def xor_data(data, key):
    return bytes(b ^ key for b in data)

def search_patterns(data, transform_name):
    """Search for interesting patterns"""

    # Search for sacred_ pattern
    if b'sacred_' in data:
        print(f"[+] {transform_name}: Found 'sacred_' pattern!")
        idx = data.find(b'sacred_')
        print(f"    Context: {data[max(0,idx-20):idx+60]}")
        return True

    # Search for JWT (eyJ)
    if b'eyJ' in data:
        print(f"[+] {transform_name}: Found potential JWT!")
        idx = data.find(b'eyJ')
        print(f"    Token: {data[idx:idx+100]}")
        return True

    # Search for Bearer
    if b'Bearer' in data:
        print(f"[+] {transform_name}: Found 'Bearer'!")
        idx = data.find(b'Bearer')
        print(f"    Context: {data[idx:idx+80]}")
        return True

    # Search for PGP markers
    if b'-----BEGIN' in data[:10000]:
        print(f"[+] {transform_name}: Found PGP marker!")
        return True

    return False

# Check original data
print("=== Checking original (no transform) ===")
search_patterns(data, "Original")

# Try XOR transformations
for key, desc in xor_keys:
    print(f"\n=== XOR with {desc} ===")
    transformed = xor_data(data, key)
    if search_patterns(transformed, f"XOR {hex(key)}"):
        # Save this transformation
        with open(f'/home/sean/ctf/NeurogridCTF_2025/Ink Vaults/pgp_extraction/transformed_xor_{hex(key)}.bin', 'wb') as f:
            f.write(transformed)

# Try rotating XOR with 靑 bytes
print("\n=== Rotating XOR with 靑 (0xe9 0x9d 0x91) ===")
qing_bytes = [0xe9, 0x9d, 0x91]
transformed = bytes(data[i] ^ qing_bytes[i % 3] for i in range(len(data)))
if search_patterns(transformed, "Rotating 靑"):
    with open('/home/sean/ctf/NeurogridCTF_2025/Ink Vaults/pgp_extraction/transformed_qing_rotate.bin', 'wb') as f:
        f.write(transformed)

# Also check for localhost IP patterns
print("\n=== Checking for IP/localhost patterns ===")
for transform_data, name in [(data, "Original"), (xor_data(data, 0x07), "XOR 0x07")]:
    if b'127.0.0.1' in transform_data or b'localhost' in transform_data:
        print(f"[+] {name}: Found localhost reference!")
    if b'http://' in transform_data or b'https://' in transform_data:
        print(f"[+] {name}: Found URL!")

print("\n[*] Search complete")
