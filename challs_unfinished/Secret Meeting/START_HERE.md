# Secret Meeting CTF - Start Here

**Challenge:** Forensics - Hard - 1000 points
**Progress:** 3/5 flags solved (60%)
**Status:** BLOCKED on .zenc file decryption

## Quick Summary

We successfully solved 3 flags:
1. ✅ Installation timestamp
2. ✅ Deletion tool used
3. ✅ Snapshot timestamp

We are BLOCKED on the final 2 flags which require decrypting:
4. ❌ Meeting ID - needs .zenc body decryption
5. ❌ Meeting duration - needs .zenc body decryption

## What We've Accomplished

### Decryption Chain (3 successful layers)
```
DPAPI Blob (Zoom.us.ini)
    ↓ dpapick3 + masterkey
Zoom Encryption Key (48 bytes)
    ↓ AES-256-CBC
CipheredPassword (48 bytes)
    ↓ AES-256-CBC
LoggerInfo (128 bytes)
    ↓ ??? UNKNOWN ???
.zenc Body (109 KB) - CANNOT DECRYPT
```

## The Problem

The 128-byte LoggerInfo contains key material, but we cannot determine how to use it to decrypt the 109KB .zenc body. We've tested:

- All standard ciphers (AES, ChaCha20, Salsa20, RC4, etc.)
- All key derivation functions (PBKDF2, HKDF, etc.)
- 320 keys extracted from memory
- All possible key/IV combinations
- XOR, compression-only, multi-layer approaches

**Nothing works.**

## Files to Read

1. **[QUICK_REFERENCE.md](QUICK_REFERENCE.md)** - Current status and key material
2. **[DECRYPTION_ATTEMPTS.md](DECRYPTION_ATTEMPTS.md)** - Complete list of what we tried
3. **[WRITEUP.md](WRITEUP.md)** - Writeup for the 3 solved flags

## Working Scripts

- `decrypt_dpapi.py` - Decrypts DPAPI blob
- `decrypt_ciphered_password.py` - Decrypts CipheredPassword field
- `verify_loggerinfo_decrypt.py` - Decrypts and verifies LoggerInfo

## Key Files

**Evidence:**
- `memory.raw` - 5 GB memory dump
- `image.001` - 2 GB disk image
- `zoom_memlog.zenc` - **THE BLOCKER** - 109KB encrypted body
- `zoomus.enc.db` - Also encrypted, also blocked

**Extracted:**
- `Zoom.us.ini` - Contains DPAPI blob (decrypted ✓)
- `dpapi_keys/` - 31 DPAPI master keys
- `masterkey_at_2594413a.bin` - The correct master key

## What You Need to Solve This

One of the following:
1. **Zoom .zenc format documentation** - How body encryption works
2. **User password** - NT hash: `c8e9430ee9a1f04828e2214ed538c20b`
3. **Zoom client reverse engineering** - Analyze Zoom.exe encryption
4. **The missing step** - How to derive body key from LoggerInfo

## Directory Structure

```
Secret Meeting/
├── START_HERE.md                    ← You are here
├── QUICK_REFERENCE.md               ← Status and keys
├── DECRYPTION_ATTEMPTS.md           ← What we tried
├── WRITEUP.md                       ← Solved flags
├── README.md                        ← Challenge description
├── FILE_INVENTORY.md                ← Complete file list
├── memory.raw                       ← 5 GB memory dump
├── image.001                        ← 2 GB disk image
├── zoom_memlog.zenc                 ← ENCRYPTED (blocker)
├── zoomus.enc.db                    ← ENCRYPTED (blocker)
├── Zoom.us.ini                      ← DPAPI blob (decrypted)
├── dpapi_keys/                      ← Master keys directory
├── decrypt_dpapi.py                 ← Working script
├── decrypt_ciphered_password.py     ← Working script
└── verify_loggerinfo_decrypt.py     ← Working script
```

## HTB Submission

- Challenge ID: `63284`
- Use MCP tool: `mcp__htb-mcp-ctf__submit_flag`
- Example: `mcp__htb-mcp-ctf__submit_flag(63284, "your_flag_here")`

## Good Luck!

This challenge requires knowledge beyond standard cryptography. The Zoom .zenc encryption format is not publicly documented, and we've exhausted all standard approaches. You may need to:

- Research Zoom's proprietary encryption
- Find leaked documentation or source code
- Reverse engineer the Zoom client
- Discover an unintended solve path

**The answer is in the encrypted data - we just need the right key.**
