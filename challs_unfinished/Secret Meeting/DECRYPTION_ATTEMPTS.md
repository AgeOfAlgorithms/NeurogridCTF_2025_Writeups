# Decryption Attempts - Secret Meeting CTF

**Status:** BLOCKED - Cannot decrypt .zenc body or zoomus.enc.db database
**Date:** 2025-11-23

## What We Successfully Decrypted

### 1. DPAPI Blob → Zoom Encryption Key
- **Source:** Zoom.us.ini (262 bytes)
- **Method:** DPAPI decryption using masterkey_at_2594413a.bin
- **Result:** 48-byte key
  ```
  1ce9ff4c9a63252a11a09e9b04dbaf10c28d604f06df3bc2017818370809b3678cd13436ee958a7f1e41d5cf70f7e5da
  ```

### 2. CipheredPassword Field
- **Source:** .zenc header
- **Method:** AES-256-CBC using DPAPI-decrypted key (key: first 32 bytes, IV: bytes 32-48)
- **Result:** 48-byte value
  ```
  4d255115e9dd08935374e77753997cb958d68e6ed56992c638ed9772edae2e1d4d241f095c1897364ddb9b8f91a8bf47
  ```

### 3. LoggerInfo Field
- **Source:** .zenc header (133 bytes with 5-byte header: `04 01 88 66 e3`)
- **Method:** AES-256-CBC using decrypted CipheredPassword (key: first 32 bytes, IV: bytes 32-48)
- **Result:** 128 bytes of structured data (entropy: 6.59 bits/byte - medium structured data, not plaintext)
  ```
  418a5b0405b8e7955a9ab72241e88eb90a78233a2d61afede35cf0f3b73de22e
  468d5c2d3665b3ff09c5582679b022379490743ec5d284d0db3375743171bd07
  7719d5acdf161a81d32f2505195a8493c567d22e1493c6864fd1aec945aad29f
  1b1563adc96b9ee408ed7f180b697b7616350c36ae8cd94a7e91cc05378a1208
  ```

## What We CANNOT Decrypt

### .zenc Body (109,120 bytes)
- **Entropy:** 7.9986 bits/byte (very high - encrypted/compressed)
- **Block alignment:** Perfect 16-byte blocks (6,820 blocks)
- **Repeating blocks:** 3.68% repeat ratio (239/6497 blocks)
- **Status:** Unable to decrypt with any tested method

### zoomus.enc.db (SQLCipher Database)
- **Size:** 110 KB
- **Status:** Unable to unlock with any extracted/derived keys

## Exhaustive Testing Performed

### Cipher Algorithms Tested
- AES-128/192/256 (CBC, ECB, CTR modes)
- ChaCha20 (8-byte and 12-byte nonces)
- Salsa20
- RC4/ARC4 (16, 24, 32, 48, 64-byte keys)
- Blowfish (CBC mode)
- 3DES (CBC mode)

### Key Material Tested
1. **Direct use of decrypted LoggerInfo (128 bytes)**
   - All 32-byte + 16-byte sliding windows (tested 81 offsets)
   - 4x 32-byte segments
   - 8x 16-byte segments
   - All combinations as key+IV pairs

2. **Alternative LoggerInfo decryption**
   - Found second valid decryption with lower entropy (6.55 vs 6.59)
   - Tested all offsets - also failed

3. **CipherSignature integers**
   - Two 66-byte RSA signature values
   - SHA256 and MD5 hashes
   - XOR combinations with other key material

4. **320 high-entropy keys** extracted from memory
   - Tested as AES-256-CBC (key+IV)
   - Tested as RC4 with various lengths

5. **Key Derivation Functions**
   - PBKDF2 (1K, 10K, 100K iterations)
   - HKDF with various salts/info parameters
   - Double SHA-256
   - Using ReceiverVersion ("V01") as salt
   - Using body first bytes as salt

### Other Approaches Tested
- XOR obfuscation (single-byte, multi-byte, repeating key)
- Direct compression (zlib, gzip, bz2, lzma, raw deflate)
- Compression after decryption
- Body header offset skipping (1, 2, 3, 4, 5, 8, 16 bytes)
- Multi-layer encryption (decrypt twice with different keys)
- Composite keys (concatenating password + logger)

## Analysis Results

### .zenc File Structure
```
[ReceiverVersion: "V01"]
[CipheredPassword: 48 bytes, DPAPI-encrypted] ✓ DECRYPTED
[CipherSignature: 2x RSA signature integers]
[LoggerInfo: 5-byte header + 128-byte ciphertext] ✓ DECRYPTED
[End\n]
[Body: 109,120 bytes] ✗ CANNOT DECRYPT
```

### Decrypted LoggerInfo Structure
The 128 decrypted bytes from LoggerInfo show:
- Medium entropy (6.59 bits/byte) - suggests structured binary data, not plaintext
- No null bytes - dense data
- No PKCS#7 padding - either unpadded or the padding is incorrect
- Four 32-byte segments with similar low entropy (~4.8 bits/byte each)

**Hypothesis:** LoggerInfo contains key material for body decryption, but:
1. Requires additional transformation we haven't found
2. Uses non-standard encryption not tested
3. Needs additional data not in the .zenc file
4. Has proprietary Zoom encryption scheme

## Potential Missing Elements

1. **User password** - The user's Windows password is unknown (NT hash: `c8e9430ee9a1f04828e2214ed538c20b`, not in rockyou.txt)

2. **Zoom-specific key derivation** - May use proprietary KDF or encryption scheme not documented

3. **Hardware-based key** - Could require machine-specific data (GUID, MAC address, etc.)

4. **Network-sourced key** - Might require key from Zoom servers (not available offline)

5. **Additional header fields** - The 5-byte header `04 01 88 66 e3` may contain cipher parameters we haven't interpreted correctly

## Files Containing Meeting Data (Encrypted)

1. **zoom_memlog.zenc** - Encrypted log file (body: 109KB)
2. **zoomus.enc.db** - SQLCipher encrypted database (110KB)
3. **Both require decryption to extract meeting ID and duration**

## Flags Status

- ✅ Flag 1: Installation timestamp - **SOLVED**
- ✅ Flag 2: Deletion tool - **SOLVED**
- ✅ Flag 3: Snapshot timestamp - **SOLVED**
- ❌ Flag 4: Meeting ID - **BLOCKED** (requires decryption)
- ❌ Flag 5: Meeting duration - **BLOCKED** (requires decryption)

## Next Steps for Future Attempts

1. **Reverse engineer Zoom client** - Analyze Zoom.exe to understand .zenc encryption
2. **Find Zoom encryption documentation** - Search for official or leaked specs
3. **Analyze similar CTF challenges** - Look for known Zoom encryption exploits
4. **Brute force user password** - More comprehensive password cracking
5. **Contact challenge author** - May have hint or unintended solve path
6. **Check for Zoom CVEs** - Known vulnerabilities in encryption implementation

## Conclusion

We successfully decrypted 3 layers (DPAPI → CipheredPassword → LoggerInfo) but cannot decrypt the final layer (body data). The encryption appears to use standard AES-256-CBC, but the key derivation from the 128-byte LoggerInfo to the body encryption key remains unknown. Without this knowledge or the user's password, the challenge cannot be completed.
