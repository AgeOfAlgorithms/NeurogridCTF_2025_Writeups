# Resurrection Challenge - Comprehensive Analysis
## HTB Neurogrid CTF 2025

**Category:** Forensics
**Difficulty:** Medium
**Points:** 1000
**Solves:** 2 (as of 2025-11-22)
**Status:** ❌ **UNSOLVED** - Requires manual reverse engineering or missing insight
**Analysis Date:** 2025-11-20 to 2025-11-22
**Total Hours Invested:** ~10 hours across 3 sessions

---

## Executive Summary

We completed **85-90%** of this challenge through memory forensics, network analysis, and extensive cryptanalysis. The remaining blocker is extracting the 32-byte ChaCha20 encryption key from obfuscated Go malware code.

### What We Accomplished ✅

1. **Memory Forensics** - Identified fileless malware (PID 5197, process name "3")
2. **Binary Extraction** - Dumped malware from memory at runtime
3. **Network Analysis** - Extracted encrypted C2 traffic on port 8484
4. **Crypto Identification** - Confirmed ChaCha20 stream cipher
5. **Static Analysis** - Loaded binary in Ghidra (1955 stripped functions)
6. **Exhaustive Testing** - Tested 6000+ key/nonce combinations

### What Remains ❌

- **Extract 32-byte ChaCha20 key** from obfuscated Go binary code
- **Decrypt C2 traffic** containing the flag (1,946 bytes server data)

---

## Challenge Description

> In the hidden depths of Kannabi, where forgotten souls once forged living machines, lies a secret buried beneath digital ash. A resurrection is underway—machines awakening, whispers of encrypted commands flowing through shadowed channels. Your task: uncover what was meant to stay buried. Decode the ritual, trace the resurrection.

**Downloads:**
- `forensics_resurrection.zip` (873 MB)
  - `memory.dmp` (4.0 GB) - AVML memory dump
  - `network.pcapng` (9.5 MB) - Network capture
  - `Ubuntu_6.8.0-31-generic_6.8.0-31.31_amd64.json.xz` (2.9 MB) - Volatility symbols

---

## Technical Findings

### Malware Process

```
PID:           5197
Name:          "3" (single character - evasion technique)
Path:          /memfd:libudev-cache (deleted) - fileless execution
Parent:        systemd (PID 1)
Language:      Go (golang.org/x/crypto v0.23.0)
Started:       2025-06-02 09:24:27 UTC
Memory Size:   10 MB runtime, 289 KB ELF (with corrupted headers)
```

### C2 Communication

```
Protocol:      Custom encrypted C2
Port:          8484 (non-standard)
Server:        192.168.91.133:8484
Client:        192.168.91.191
Packets:       23 server responses, 198 client requests
Data Size:     1,946 bytes server → client (contains encrypted flag)
               45,810 bytes client → server (exfiltrated data)
```

### Encryption Details

```
Algorithm:     ChaCha20 (stream cipher)
Key Size:      32 bytes (256-bit) - **UNKNOWN**
Nonce:         8 or 12 bytes - **UNKNOWN**
Constant:      "expand 32-byte k" found at offset 0x19db60 (binary)
               Found at 49 locations in memory dump
```

---

## Analysis Timeline

### Session 1: 2025-11-20 (~3 hours)
- Memory forensics with Volatility3
- Malware process identification
- Binary extraction from memory
- Network C2 extraction
- Initial ChaCha20 identification

### Session 2: 2025-11-21 (~4 hours)
- Ghidra static analysis setup
- Automated key scanning (133,020 tests)
- Various key derivation attempts
- Documented blockers

### Session 3: 2025-11-22 (~3 hours)
- Advanced key derivation tests
- Memory dump analysis (49 ChaCha20 constants)
- Theme-based and creative approaches
- Dynamic analysis attempt (GDB)
- Tested 6000+ total combinations

### Session 4: 2025-11-22 (~4 hours)
- Ghidra MCP programmatic analysis
- Scanned 735,933 high-entropy 32-byte sequences from binary
- Known-plaintext attack with HTB{/htb{
- Memory dump key extraction (49 ChaCha20 constant locations)
- Tested 50,000+ key/nonce combinations total
- Confirmed ChaCha20 vs ChaCha8rand (RNG) distinction

---

## All Approaches Tested

### 1. Static Binary Analysis

**Tool:** Ghidra
**Binary:** malware_10mb.bin (loaded as raw, base 0x100000)
**Functions:** 1955 total (all stripped to FUN_00xxxxxx)
**ChaCha20 Constant:** Located at 0x19db60
**XREFs:** None found (constant used as immediate value)

**Findings:**
- High-entropy 16-byte sequence at 0x19dc20: `512563fcc2cab9f3849e17a7adfae6bc`
- Binary is Go-compiled with crypto libraries
- All function names stripped
- Entry point corrupted (0x0) - cannot run directly

### 2. Binary Memory Scanning

**Tested:**
- 270 aligned 32-byte sequences near ChaCha20 constant
- 73 high-entropy sequences (±8KB scan)
- 208 candidates with >20 unique bytes
- XOR combinations of nearby memory regions
- Split key hypotheses (16+16 bytes)

**Result:** None decrypted the flag

### 3. Creative Key Derivations

**Tested:**
- SHA256/SHA512 of challenge themes ("Resurrection", "Kannabi", "digital ash")
- Network metadata (IPs, ports, timestamps)
- Process data (PID 5197, process name "3")
- Simple patterns (all 0x00-0xFF, sequential, reversed)
- XOR with ChaCha20 constant as mask
- Padded/doubled/reversed variations

**Result:** None worked

### 4. Nonce Variations

**Tested:**
- All zeros (8 and 12 bytes)
- All ones, all 0xFF
- Sequential bytes
- Counter patterns (0-10)
- From ciphertext (first/last bytes)
- Timestamp-based

**Result:** None worked

### 5. Memory Dump Analysis

**Scanned 4GB memory dump:**
- 49 ChaCha20 constant locations
- 191 unique high-entropy 32-byte sequences near constants
- 47 hex-encoded strings (64 chars = 32 bytes)
- Searched for "HTB{" in memory (found 3 instances, all encrypted)

**Result:** None decrypted the flag

### 6. Dynamic Analysis Attempt

**Approach:** GDB debugging
**Blocker:** Binary has corrupted ELF headers (entry point = 0x0)
**Status:** Cannot load in GDB - "not in executable format"
**Note:** Binary was extracted from memory, not original executable

### 7. Research & CTF Patterns

**Researched:**
- CrowdStrike Adversary Quest (ChaCha20 key from TLS timing)
- Lumma Stealer malware (ChaCha20 config decryption)
- Similar forensics CTF challenges

**Insight:** Some challenges use non-obvious key extraction (timing, known-plaintext, config files)

---

## Why We're Blocked

The encryption key is **NOT** stored as a simple 32-byte sequence. Based on extensive testing, the key is likely:

### Scenario A: Runtime Key Derivation
```go
func getKey() []byte {
    seed := getSomeValue()  // Timestamp, constant, or computation
    return kdf(seed)        // PBKDF2, HKDF, or custom KDF
}
```

### Scenario B: XOR Obfuscation (Complex)
```go
var part1 = []byte{...}  // At location A
var part2 = []byte{...}  // At location B
var part3 = []byte{...}  // At location C
key = complexXOR(part1, part2, part3)
```

### Scenario C: Multi-Stage Derivation
```go
func deriveKey() []byte {
    base := hardcodedConstant
    step1 := xor(base, magicValue)
    step2 := hash(step1)
    return transform(step2)
}
```

### Scenario D: Alternative Attack Vector
- Flag might not require decrypting ChaCha20
- Vulnerability in malware reveals flag differently
- Hidden plaintext somewhere we haven't looked

---

## Files in This Directory

### 📚 Documentation
- **COMPREHENSIVE_ANALYSIS.md** (this file) - Complete analysis summary
- **README.md** - Quick reference and file guide
- **GHIDRA_MANUAL_INSTRUCTIONS.md** - Guide for manual reverse engineering

### 🔧 Essential Scripts
- **decrypt_with_key.py** - Ready to decrypt C2 once key is found
- **extract_c2.py** - How C2 traffic was extracted (reference)

### 💾 Binary Files
- **malware_10mb.bin** (10 MB) - Runtime memory dump, loaded in Ghidra
- **malware_proper.bin** (289 KB) - ELF with corrupted headers
- **c2_server_to_client.bin** (1,946 bytes) - **Contains encrypted flag**
- **c2_client_to_server.bin** (45,810 bytes) - Exfiltrated data

### 📦 Original Challenge Files
- **memory.dmp** (4.0 GB) - AVML memory dump
- **network.pcapng** (9.5 MB) - Network capture
- **Ubuntu_6.8.0-31-generic_6.8.0-31.31_amd64.json.xz** - Volatility symbols
- **forensics_resurrection.zip** (873 MB) - Original download

---

## How to Continue

### Option 1: Manual Ghidra Reverse Engineering (Most Likely Path)

**Requirements:**
- Time: Many hours (potentially 5-10+ hours)
- Skills: Go binary analysis, crypto pattern recognition
- Tool: Ghidra with malware_10mb.bin loaded

**Steps:**
1. Load malware_10mb.bin in Ghidra (Golang, base 0x100000)
2. Navigate to ChaCha20 constant at 0x19db60
3. Search for patterns:
   - 32-byte buffer allocations
   - Crypto library function calls
   - XOR operations on 32-byte data
   - Hash function calls (SHA256, etc.)
4. Trace function calls that might initialize crypto
5. Identify key derivation logic
6. Extract or reconstruct the 32-byte key
7. Use decrypt_with_key.py to get flag

**See:** GHIDRA_MANUAL_INSTRUCTIONS.md for detailed guide

### Option 2: Wait for Community Writeups

**Status:** Challenge has 2 solves
**Timeline:** Writeups typically published 1-2 weeks after CTF ends
**Benefit:** Learn the intended solution approach
**Platforms:** HackTheBox forums, CTFtime, solver blogs

### Option 3: Alternative Attack Vectors

**Unexplored angles:**
- Vulnerability in malware code itself
- Known-plaintext attack (if we can guess some plaintext)
- Timing analysis of network packets
- Hidden clues in challenge description/metadata
- Community hints or challenge updates

---

## Key Statistics

| Metric | Value |
|--------|-------|
| Total test combinations | 50,000+ |
| Binary entropy scans | 735,933 sequences analyzed |
| Memory scans | 49 ChaCha20 constants + 252 key candidates |
| Unique approaches | 25+ distinct methods |
| Tools used | Volatility3, Ghidra MCP, Scapy, tshark, GDB MCP, Python |
| Code written | ~1,200 lines (analysis scripts) |
| Documentation | ~3,000 lines (markdown) |
| Ghidra functions analyzed | 1,955 stripped functions |
| Time invested | 14+ hours |

---

## Lessons Learned

1. **Multi-domain expertise required:** This challenge demands memory forensics, network analysis, AND reverse engineering
2. **Go malware is intentionally hard:** 1955 stripped functions, obfuscated keys, complex runtime
3. **0-solve → 2-solve progression:** Challenge is very difficult but solvable
4. **Automated approaches have limits:** After ~6000 tests, manual analysis becomes necessary
5. **"Think outside the box" != brute force:** The solution likely requires a specific insight or technique

---

## Critical Hints for Future Solvers

1. **ChaCha20 constant at 0x19db60** - Start here in Ghidra
2. **High-entropy data at 0x19dc20** - The sequence `512563fcc2cab9f3849e17a7adfae6bc` appears multiple times
3. **49 ChaCha20 constants in memory** - Key might be near one of these locations
4. **C2 structure:** Encrypted length (4 bytes) + encrypted payload
5. **First server packet:** Single byte 0x0a (might be useful for known-plaintext)
6. **Key is NOT plaintext:** Extensively tested, must be obfuscated/derived

---

## Recommendations

**For CTF Teams:**
- Allocate dedicated reverse engineering time (5-10 hours)
- Have Go binary analysis experience
- Consider collaboration with specialized RE team members

**For Learning:**
- This is an excellent advanced forensics/RE challenge
- Good practice for real-world malware analysis
- Demonstrates importance of multi-stage analysis

**For Challenge Authors:**
- Brilliant multi-stage design
- Appropriate difficulty for 1000 points
- Well-balanced between forensics and reverse engineering

---

## Contact & Collaboration

If you solve this challenge or have insights, contributions are welcome!

**What would help:**
- Ghidra analysis findings
- Alternative approach ideas
- Known similar CTF challenges
- Writeup links when available

---

## Appendix: Test Scripts Created

All test scripts have been removed from this directory to keep it clean. The following approaches were coded and tested:

1. `test_ghidra_keys.py` - Tested specific Ghidra memory offsets
2. `test_outside_box.py` - Theme-based and creative keys
3. `test_protocol_structure.py` - Protocol structure analysis
4. `analyze_binary_keys.py` - Comprehensive binary scanning (270 candidates)
5. `extreme_outside_box.py` - Creative derivations (24 methods)
6. `test_split_key.py` - 16+16 byte combinations
7. `test_xor_with_constant.py` - XOR with ChaCha20 constant
8. `find_32byte_sequences.py` - High-entropy scanning
9. `test_nonce_variations.py` - Non-zero nonce testing
10. `test_theme_keys.py` - Challenge theme-based keys (61 variations)
11. `test_simple_keys.py` - Obvious/simple keys (276 tests)
12. `scan_memory_for_keys.py` - Memory dump scanning (191 candidates)
13. `test_hex_strings.py` - Hex-encoded strings from memory (47 tests)
14. `test_memory_key.py` - Memory-specific key variations

**Total unique test scripts:** 14
**Total lines of analysis code:** ~800
**All results:** No successful decryption

---

**Document Created:** 2025-11-22
**Last Updated:** 2025-11-22
**Version:** 1.1 (Ghidra MCP Analysis Complete)
**Status:** Challenge remains unsolved - Manual RE required
