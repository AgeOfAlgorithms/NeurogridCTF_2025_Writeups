# Secret Meeting CTF - Quick Reference

**Status:** 3/5 Flags Solved - BLOCKED on decryption
**Category:** Forensics | **Difficulty:** Hard | **Points:** 1000

## Current Progress: 3/5 Flags (60%)

### ✅ Solved
1. **Installation Timestamp:** `2024-12-17 08:51:01` UTC
2. **Deletion Tool:** `SDelete`
3. **Snapshot Timestamp:** `2025-03-06 17:17:33` UTC

### ❌ Unsolved - BLOCKED
4. **Meeting ID:** Encrypted in .zenc body or zoomus.enc.db
5. **Meeting Duration:** Encrypted in .zenc body or zoomus.enc.db

## Decryption Progress

### ✅ Successfully Decrypted (3 layers)
```
1. DPAPI Blob (Zoom.us.ini)
   ↓ [dpapick3 + masterkey_at_2594413a.bin]
   48-byte Zoom key

2. CipheredPassword (.zenc header)
   ↓ [AES-256-CBC with DPAPI key]
   48-byte value

3. LoggerInfo (.zenc header)
   ↓ [AES-256-CBC with CipheredPassword]
   128 bytes (entropy: 6.59 - structured data)
```

### ❌ Cannot Decrypt (BLOCKER)
```
4. .zenc Body (109,120 bytes)
   - Entropy: 7.9986 (very high - encrypted)
   - Perfect 16-byte block alignment
   - Unknown key derivation from LoggerInfo
   - Tested: All standard ciphers, 320 memory keys, KDFs
   - Result: FAILED

5. zoomus.enc.db (110 KB SQLCipher)
   - Tested: All derived keys, memory keys
   - Requires: Unknown key or user password
   - Result: FAILED
```

## Key Material Available

**DPAPI Decrypted Key (48 bytes):**
```
1ce9ff4c9a63252a11a09e9b04dbaf10c28d604f06df3bc2017818370809b3678cd13436ee958a7f1e41d5cf70f7e5da
```

**Decrypted CipheredPassword (48 bytes):**
```
4d255115e9dd08935374e77753997cb958d68e6ed56992c638ed9772edae2e1d4d241f095c1897364ddb9b8f91a8bf47
```

**Decrypted LoggerInfo (128 bytes):**
```
418a5b0405b8e7955a9ab72241e88eb90a78233a2d61afede35cf0f3b73de22e
468d5c2d3665b3ff09c5582679b022379490743ec5d284d0db3375743171bd07
7719d5acdf161a81d32f2505195a8493c567d22e1493c6864fd1aec945aad29f
1b1563adc96b9ee408ed7f180b697b7616350c36ae8cd94a7e91cc05378a1208
```

## Working Scripts

1. **decrypt_dpapi.py** - Decrypts DPAPI blob from Zoom.us.ini
2. **decrypt_ciphered_password.py** - Decrypts CipheredPassword from .zenc
3. **verify_loggerinfo_decrypt.py** - Verifies LoggerInfo decryption

## What We Tried (All Failed)

- **Ciphers:** AES (CBC/ECB/CTR), ChaCha20, Salsa20, RC4, Blowfish, 3DES
- **Keys:** 320 memory keys, LoggerInfo segments, CipherSignature values
- **KDFs:** PBKDF2 (1K-100K iterations), HKDF, double SHA-256
- **Other:** XOR, compression-only, multi-layer, offset skipping

See [DECRYPTION_ATTEMPTS.md](DECRYPTION_ATTEMPTS.md) for complete analysis.

## Challenge Files

**Evidence:**
- `memory.raw` - 5 GB memory dump
- `image.001` - 2 GB disk image (NTFS)
- `zoom_memlog.zenc` - Encrypted log (BLOCKED HERE)
- `zoomus.enc.db` - Encrypted database (BLOCKED HERE)
- `Zoom.us.ini` - DPAPI encrypted key (✓ decrypted)

**Documentation:**
- [README.md](README.md) - Challenge description
- [WRITEUP.md](WRITEUP.md) - Solved flags writeup
- [DECRYPTION_ATTEMPTS.md](DECRYPTION_ATTEMPTS.md) - Decryption analysis
- [FILE_INVENTORY.md](FILE_INVENTORY.md) - Complete file listing

## The Blocker

**Unknown:** How to derive the body encryption key from the 128-byte LoggerInfo

**Possibilities:**
1. Proprietary Zoom encryption scheme (not publicly documented)
2. Requires user password (NT hash: `c8e9430ee9a1f04828e2214ed538c20b`)
3. Needs additional machine-specific data
4. Non-standard key derivation we haven't found

## Next Steps

To complete this challenge, you need to either:
1. Reverse engineer Zoom client encryption
2. Find Zoom .zenc format documentation
3. Crack the user password
4. Discover the missing key derivation step

**Challenge appears to require knowledge beyond standard cryptography.**
