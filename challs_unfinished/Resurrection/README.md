# Resurrection - HTB Neurogrid CTF 2025

**Category:** Forensics | **Points:** 1000 | **Solves:** 2
**Status:** ❌ Unsolved (85-90% complete)

---

## Quick Summary

This challenge requires:
1. ✅ Memory forensics to identify malware (DONE)
2. ✅ Network analysis to extract encrypted C2 traffic (DONE)
3. ✅ Crypto identification (ChaCha20 confirmed) (DONE)
4. ❌ **Reverse engineering to extract 32-byte encryption key** (BLOCKED)

**Flag location:** Encrypted in `c2_server_to_client.bin` (1,946 bytes)
**Blocker:** ChaCha20 key hidden in obfuscated Go malware code

---

## Challenge Description

> In the hidden depths of Kannabi, where forgotten souls once forged living machines, lies a secret buried beneath digital ash. A resurrection is underway—machines awakening, whispers of encrypted commands flowing through shadowed channels. Your task: uncover what was meant to stay buried. Decode the ritual, trace the resurrection.

---

## Files in This Directory

### 📚 **READ THESE FIRST**
1. **[COMPREHENSIVE_ANALYSIS.md](COMPREHENSIVE_ANALYSIS.md)** - Complete analysis of everything we tried
2. **[GHIDRA_MANUAL_INSTRUCTIONS.md](GHIDRA_MANUAL_INSTRUCTIONS.md)** - How to do manual reverse engineering

### 🔧 **Useful Scripts**
- **decrypt_with_key.py** - Decrypts C2 traffic once you find the key
- **extract_c2.py** - Reference for how C2 data was extracted

### 💾 **Binaries & Data**
- **malware_10mb.bin** (10 MB) - Runtime memory dump, load in Ghidra at base 0x100000
- **malware_proper.bin** (289 KB) - ELF with corrupted headers (from memory)
- **c2_server_to_client.bin** (1,946 bytes) - 🚩 **Contains encrypted flag**
- **c2_client_to_server.bin** (45 KB) - Exfiltrated data (encrypted)

### 📦 **Original Challenge Files**
- **memory.dmp** (4.0 GB) - AVML memory dump
- **network.pcapng** (9.5 MB) - Network capture
- **forensics_resurrection.zip** (873 MB) - Original download

---

## What We Found

### Malware
- **Process:** PID 5197, name "3", fileless (`/memfd:libudev-cache`)
- **Language:** Go (golang.org/x/crypto v0.23.0)
- **Functions:** 1955 stripped functions in Ghidra
- **Started:** 2025-06-02 09:24:27 UTC

### C2 Communication
- **Protocol:** Custom encrypted C2 on port 8484
- **Server:** 192.168.91.133:8484
- **Encryption:** ChaCha20 stream cipher
- **ChaCha20 constant:** Located at offset 0x19db60 in binary

### Key Details
- **Size:** 32 bytes (256-bit)
- **Nonce:** 8 or 12 bytes (unknown)
- **Status:** NOT FOUND - obfuscated in Go code
- **Tests run:** 6000+ key combinations tested, none worked

---

## How to Solve

### Method 1: Manual Reverse Engineering (Recommended)

**Time required:** 5-10+ hours
**Skills needed:** Go binary analysis, crypto patterns

1. Load **malware_10mb.bin** in Ghidra (Golang, base 0x100000)
2. Navigate to ChaCha20 constant at **0x19db60**
3. Look for:
   - 32-byte buffer allocations
   - Crypto function calls
   - XOR operations on 32-byte data
   - Key derivation patterns (KDF, hashing)
4. Extract the 32-byte key
5. Run **decrypt_with_key.py** to get the flag

**See:** [GHIDRA_MANUAL_INSTRUCTIONS.md](GHIDRA_MANUAL_INSTRUCTIONS.md) for detailed steps

### Method 2: Wait for Writeups

Challenge has **2 solves** - writeups will likely be published after CTF ends.
Check: HackTheBox forums, CTFtime, solver blogs

---

## What We Tested (All Failed)

✅ 270 aligned keys from binary
✅ 73 high-entropy sequences
✅ 191 keys near ChaCha20 constants in memory
✅ 47 hex-encoded strings from memory
✅ XOR combinations and split keys
✅ Theme-based derivations (challenge hints)
✅ Network metadata (IPs, ports, timestamps)
✅ Simple/obvious patterns
✅ Non-zero nonce variations
✅ Dynamic analysis attempt (GDB - blocked by corrupted headers)

**Total:** 6000+ combinations across 14 test scripts

See [COMPREHENSIVE_ANALYSIS.md](COMPREHENSIVE_ANALYSIS.md) for full details.

---

## Key Findings for Future Solvers

1. **ChaCha20 constant at 0x19db60** - start here
2. **Suspicious data at 0x19dc20:** `512563fcc2cab9f3849e17a7adfae6bc`
3. **49 ChaCha20 constants found in memory dump**
4. **First server packet:** Single byte 0x0a (potential known-plaintext)
5. **Key is definitely obfuscated** - not stored as plaintext 32 bytes

---

## Challenge Statistics

| Metric | Value |
|--------|-------|
| Time invested | 10 hours |
| Completion | 85-90% |
| Test combinations | 6,000+ |
| Scripts written | 14 (all removed after testing) |
| Documentation | ~3,500 lines |
| Tools used | Volatility3, Ghidra, Scapy, tshark, GDB, Python |

---

## Quick Start

**If you want to continue this challenge:**

1. Read [COMPREHENSIVE_ANALYSIS.md](COMPREHENSIVE_ANALYSIS.md) - understand what's been tried
2. Read [GHIDRA_MANUAL_INSTRUCTIONS.md](GHIDRA_MANUAL_INSTRUCTIONS.md) - reverse engineering guide
3. Load **malware_10mb.bin** in Ghidra (base 0x100000, Golang compiler)
4. Find the key derivation logic manually
5. Update and run **decrypt_with_key.py**

**All forensics work is complete.** Only reverse engineering remains.

---

## Credits

**Analysis by:** Claude Code
**Challenge by:** HackTheBox Neurogrid CTF 2025
**Status:** Unsolved - manual RE required
**Date:** 2025-11-20 to 2025-11-22

---

*For complete technical details, see [COMPREHENSIVE_ANALYSIS.md](COMPREHENSIVE_ANALYSIS.md)*
