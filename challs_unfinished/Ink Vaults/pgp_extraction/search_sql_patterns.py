#!/usr/bin/env python3
"""
Search for SQL commands or API tokens in transformed PGP data
Author: Claude
Purpose: Find hidden SQL UPDATE commands or guardian tokens
Created: 2025-11-23
"""

import re

# Read PGP key data
with open('/home/sean/ctf/NeurogridCTF_2025/Ink Vaults/pgp_extraction/scroll7_pgp_key.bin', 'rb') as f:
    data = f.read()

print(f"Data size: {len(data)} bytes\n")

def xor_data(data, key):
    if isinstance(key, int):
        return bytes(b ^ key for b in data)
    else:
        return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))

def search_sql(data, transform_name):
    """Search for SQL patterns"""
    text = data.decode('latin-1')  # Use latin-1 to handle all bytes

    # Search for UPDATE statements
    if re.search(r'UPDATE\s+scrolls', text, re.IGNORECASE):
        print(f"[+] {transform_name}: Found UPDATE scrolls!")
        matches = re.findall(r'UPDATE\s+scrolls[^;]{0,200}', text, re.IGNORECASE)
        for match in matches:
            print(f"    {match}")
        return True

    # Search for sacred_ tokens
    if 'sacred_' in text:
        print(f"[+] {transform_name}: Found sacred_ token!")
        matches = re.findall(r'sacred_[A-Za-z0-9]{20,50}', text)
        for match in matches:
            print(f"    {match}")
        return True

    # Search for SET commands
    if re.search(r'SET\s+scroll_availability', text, re.IGNORECASE):
        print(f"[+] {transform_name}: Found SET scroll_availability!")
        matches = re.findall(r'SET\s+scroll_availability[^;]{0,100}', text, re.IGNORECASE)
        for match in matches:
            print(f"    {match}")
        return True

    return False

# Try XOR with various keys
xor_keys = [
    (0x07, "Bell (0x07)"),
    (0x80, "High bit flip (0x80)"),
    (0xff, "Bitwise NOT (0xff)"),
    (bytes([0x07, 0x00]), "Alternating 07-00"),
    (bytes([0x07] * 3), "Triple 07"),
    (b"07", "ASCII '07'"),
    (b"QING", "QING bytes"),
    (bytes([0xe9, 0x9d, 0x91]), "UTF-8 靑"),
]

for key, desc in xor_keys:
    print(f"=== {desc} ===")
    try:
        transformed = xor_data(data, key)
        search_sql(transformed, desc)
    except Exception as e:
        print(f"Error: {e}")
    print()

print("[*] Search complete")
