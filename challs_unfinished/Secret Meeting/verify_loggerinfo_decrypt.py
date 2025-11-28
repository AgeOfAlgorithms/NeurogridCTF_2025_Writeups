#!/usr/bin/env python3
"""
Verify LoggerInfo decryption step-by-step
Author: CTF investigation
Date: 2025-11-23
Purpose: Double-check that LoggerInfo was decrypted correctly
"""

import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Read the .zenc header to extract LoggerInfo
with open('zoom_memlog.zenc', 'rb') as f:
    data = f.read()

header_end = data.find(b'End\n')
if header_end == -1:
    header_end = data.find(b'End\r\n')

header = data[:header_end]

# Extract LoggerInfo base64
logger_start = header.find(b'LoggerInfo:') + len(b'LoggerInfo:')
logger_end = header.find(b'End', logger_start)
logger_info_b64 = header[logger_start:logger_end].strip()

print("=" * 80)
print("Verifying LoggerInfo Decryption")
print("=" * 80)

print(f"\n1. LoggerInfo (base64): {len(logger_info_b64)} bytes")
print(f"   {logger_info_b64[:80]}")

# Decode from base64
logger_info_encrypted = base64.b64decode(logger_info_b64)
print(f"\n2. LoggerInfo (decoded): {len(logger_info_encrypted)} bytes")
print(f"   Hex: {logger_info_encrypted.hex()[:80]}...")

# Extract header and ciphertext
header_bytes = logger_info_encrypted[:5]
ciphertext = logger_info_encrypted[5:]

print(f"\n3. Header: {header_bytes.hex()} ({len(header_bytes)} bytes)")
print(f"   Ciphertext: {len(ciphertext)} bytes")

# Decrypted CipheredPassword (our key source)
decrypted_pw_hex = "4d255115e9dd08935374e77753997cb958d68e6ed56992c638ed9772edae2e1d4d241f095c1897364ddb9b8f91a8bf47"
decrypted_pw = bytes.fromhex(decrypted_pw_hex)

print(f"\n4. Using decrypted CipheredPassword as key source:")
print(f"   Total length: {len(decrypted_pw)} bytes")
print(f"   Key (first 32): {decrypted_pw[:32].hex()}")
print(f"   IV (bytes 32-48): {decrypted_pw[32:48].hex()}")

# Decrypt
key = decrypted_pw[:32]
iv = decrypted_pw[32:48]

cipher = AES.new(key, AES.MODE_CBC, iv)
decrypted_logger = cipher.decrypt(ciphertext)

print(f"\n5. Decrypted LoggerInfo: {len(decrypted_logger)} bytes")
print(f"   Hex: {decrypted_logger.hex()}")

# Check if it can be unpadded
try:
    unpadded = unpad(decrypted_logger, 16)
    print(f"\n6. Unpadded successfully: {len(unpadded)} bytes")
    print(f"   This means the decryption is CORRECT")
    print(f"   Unpadded hex: {unpadded.hex()}")
except Exception as e:
    print(f"\n6. Cannot unpad: {e}")
    print(f"   This could mean:")
    print(f"   - Decryption is correct but data isn't padded")
    print(f"   - Decryption is wrong")
    print(f"   - The 128 bytes are raw binary data, not text")

# Calculate entropy to see if it looks encrypted or structured
import math
def calculate_entropy(data):
    if not data:
        return 0
    frequency = {}
    for byte in data:
        frequency[byte] = frequency.get(byte, 0) + 1
    entropy = 0
    for count in frequency.values():
        probability = count / len(data)
        entropy -= probability * math.log2(probability)
    return entropy

entropy = calculate_entropy(decrypted_logger)
print(f"\n7. Entropy analysis of decrypted LoggerInfo:")
print(f"   Entropy: {entropy:.4f} bits/byte")
print(f"   Interpretation: {'High (likely encrypted/random)' if entropy > 7.0 else 'Medium (structured data)' if entropy > 5.0 else 'Low (plaintext)'}")

# Save for inspection
with open('decrypted_loggerinfo_verified.bin', 'wb') as f:
    f.write(decrypted_logger)

print(f"\n8. Saved to: decrypted_loggerinfo_verified.bin")

print("\n" + "=" * 80)
print("Now let's check if there are other .zenc files we haven't tried")
print("=" * 80)

import glob
zenc_files = glob.glob('**/*.zenc', recursive=True)
print(f"\nFound {len(zenc_files)} .zenc files:")
for f in zenc_files:
    import os
    size = os.path.getsize(f)
    print(f"  {f}: {size} bytes")
