#!/usr/bin/env python3
"""
Transform PGP Key - Ink Vaults
Purpose: Apply "clapper-less bell" transformation (XOR with 0x07) to extract real PGP key
"""

import sys

def xor_transform(data, key):
    """XOR transform with a single byte key"""
    return bytes(b ^ key for b in data)

# Read the corrupted PGP key
with open('/home/sean/ctf/NeurogridCTF_2025/Ink Vaults/pgp_extraction/scroll7_pgp_key.bin', 'rb') as f:
    corrupted_data = f.read()

print(f"Original data size: {len(corrupted_data)} bytes")
print(f"First 32 bytes (hex): {corrupted_data[:32].hex()}")

# Try XOR with 0x07 (bell character - "clapper-less bell")
transformed = xor_transform(corrupted_data, 0x07)

print(f"\nTransformed with XOR 0x07:")
print(f"First 32 bytes (hex): {transformed[:32].hex()}")
print(f"First 100 bytes (ascii attempt): {transformed[:100]}")

# Save transformed data
with open('/home/sean/ctf/NeurogridCTF_2025/Ink Vaults/pgp_extraction/scroll7_pgp_transformed.bin', 'wb') as f:
    f.write(transformed)

# Check if it looks like valid PGP
if b'-----BEGIN' in transformed or b'PGP' in transformed[:1000]:
    print("\n[+] Found PGP markers in transformed data!")

# Search for JWT patterns
if b'eyJ' in transformed:
    print("\n[+] Found potential JWT token!")
    idx = transformed.find(b'eyJ')
    token_data = transformed[idx:idx+500]
    print(f"Token area: {token_data[:200]}")

# Search for "sacred_" pattern (like the API keys we found)
if b'sacred_' in transformed:
    print("\n[+] Found 'sacred_' pattern!")
    idx = transformed.find(b'sacred_')
    key_data = transformed[idx:idx+100]
    print(f"Key area: {key_data}")

print("\n[*] Transformed data saved to scroll7_pgp_transformed.bin")
