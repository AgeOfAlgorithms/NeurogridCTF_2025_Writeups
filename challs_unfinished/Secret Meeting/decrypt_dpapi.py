#!/usr/bin/env python3
"""
Decrypt DPAPI blob using extracted master key
Author: CTF solve attempt
Date: 2025-11-23
Purpose: Extract Zoom SQLCipher database key from DPAPI-encrypted blob
"""

import sys
import base64

print("=" * 80)
print("DPAPI Blob Decryption Attempt")
print("=" * 80)

# Step 1: Extract DPAPI blob from Zoom.us.ini
print("\n[1] Reading Zoom.us.ini...")
with open('Zoom.us.ini', 'r') as f:
    for line in f:
        if 'win_osencrypt_key' in line:
            key_data = line.split('=')[1].strip()
            if key_data.startswith('ZWOSKEY'):
                key_data = key_data[7:]  # Remove prefix
            
            print(f"Found key data (first 50 chars): {key_data[:50]}...")
            
            # Decode base64
            dpapi_blob = base64.b64decode(key_data)
            print(f"DPAPI blob size: {len(dpapi_blob)} bytes")
            
            # Save for inspection
            with open('dpapi_blob_raw.bin', 'wb') as bf:
                bf.write(dpapi_blob)
            print("Saved to: dpapi_blob_raw.bin")
            break

# Step 2: Load extracted master key
print("\n[2] Loading extracted master key...")
with open('masterkey_candidate.bin', 'rb') as mf:
    masterkey = mf.read()
print(f"Master key size: {len(masterkey)} bytes")
print(f"Master key (hex): {masterkey.hex()}")

# Step 3: Try to decrypt using dpapick3
print("\n[3] Attempting decryption with dpapick3...")
try:
    # Try importing in conda environment
    import subprocess
    result = subprocess.run([
        '/home/sean/anaconda3/envs/ctf/bin/python3',
        '-c',
        '''
import base64
from dpapick3 import blob

# Load blob
with open("dpapi_blob_raw.bin", "rb") as f:
    dpapi_bytes = f.read()

# Load master key  
with open("masterkey_candidate.bin", "rb") as f:
    masterkey = f.read()

# Parse and decrypt
dpapi_obj = blob.DPAPIBlob(dpapi_bytes)
print(f"DPAPI GUID: {dpapi_obj.mkguid}")
print(f"DPAPI version: {dpapi_obj.version}")

decrypted = dpapi_obj.decrypt(masterkey)
if decrypted:
    print(f"SUCCESS! Decrypted {len(decrypted)} bytes")
    print(f"Hex: {decrypted.hex()}")
    with open("zoom_key_decrypted.bin", "wb") as f:
        f.write(decrypted)
    print("Saved to: zoom_key_decrypted.bin")
else:
    print("Decryption returned None/empty")
'''
    ], capture_output=True, text=True, timeout=30)
    
    print("STDOUT:")
    print(result.stdout)
    if result.stderr:
        print("STDERR:")
        print(result.stderr)
    print(f"Return code: {result.returncode}")
    
except Exception as e:
    print(f"Error running decryption: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 80)
print("Script complete")
