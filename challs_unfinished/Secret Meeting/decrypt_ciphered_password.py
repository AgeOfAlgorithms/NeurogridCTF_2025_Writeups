#!/usr/bin/env python3
"""
Try to decrypt the CipheredPassword from .zenc file using DPAPI master keys
"""
from dpapick3 import blob
import glob
import base64

# The CipheredPassword from zenc file header
ciphered_pw_b64 = "g0t5JWYsmo90mpbm8bFuCh/3bnodWrK7hRo/dwZi1FOnOB7V1/hmFYbxTVKOXqQa"
ciphered_pw_bytes = base64.b64decode(ciphered_pw_b64)

print(f"CipheredPassword: {len(ciphered_pw_bytes)} bytes")
print(f"Hex: {ciphered_pw_bytes.hex()}\n")

# This might just be the raw AES key (not DPAPI encrypted)
# But the format suggests it could be a DPAPI blob or encrypted key

# Try it as-is first (32 bytes key + 16 bytes IV)
if len(ciphered_pw_bytes) == 48:
    print("It's 48 bytes - could be AES-256 key (32) + IV (16)")
    print("Already tried this and it didn't work...\n")

# Check if any DPAPI master keys can decrypt something related
print("Checking if this matches any known patterns...")

# Maybe the cipheredpassword.bin we have is already the decrypted form?
# Let's check what we have
print("\nChecking existing key files:")
for keyfile in ['ciphered_password.bin', 'dpapi_from_zoom_ini.bin']:
    try:
        with open(keyfile, 'rb') as f:
            data = f.read()
        print(f"  {keyfile}: {len(data)} bytes, hex={data.hex()[:64]}...")
    except FileNotFoundError:
        pass
