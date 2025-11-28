# Secret Meeting CTF - Attempt Analysis

**Date:** 2025-11-23
**Status:** FAILED - Cannot decrypt meeting data
**Challenge:** HackTheBox Neurogrid CTF - Secret Meeting (ID: 63284)
**Flags Solved:** 3 out of 5 (60%)

## Successfully Solved Flags

### ✅ Flag 1: Installation Timestamp
- **Answer:** `2024-12-17 08:51:01` UTC
- **Method:** Volatility 3 registry analysis on memory dump
- **Status:** CONFIRMED (submitted successfully)

### ✅ Flag 2: Deletion Tool
- **Answer:** `SDelete` (Sysinternals secure deletion tool)
- **Method:** Memory dump string analysis, found 624 occurrences
- **Status:** CONFIRMED (submitted successfully)

### ✅ Flag 3: Snapshot Timestamp
- **Answer:** `2025-03-06 17:17:33` UTC
- **Method:** Volume Shadow Copy (VSS) metadata analysis
- **Status:** CONFIRMED (submitted successfully)

## Unsolved Flags (The Blockers)

### ❌ Flag 4: Meeting ID
**Status:** FAILED - Cannot extract from encrypted sources

**What Was Tried:**
1. **Memory dump search:** Found `33857482969` in Windows Search index, submitted but WRONG
   - Error: This was a timestamp/metadata value, not actual meeting ID
   - Lesson: Need to verify context, not just pattern match

2. **Browser/Cache analysis:** Searched Edge_History, ActivitiesCache.db, WebCacheV01.dat, NTUSER.DAT
   - Found various 10-digit numbers, but none in Zoom meeting context
   - No zoom.us/j/{id} URLs found

3. **Registry hive analysis:** Searched NTUSER.DAT for patterns
   - Found 249 numbers, but none verifiable as meeting IDs
   - Most were Windows timestamps/binary data

4. **.zenc file decryption:** Attempted multiple approaches
   - Decrypted DPAPI blob successfully → 48-byte key
   - Decrypted CipheredPassword with DPAPI key → 48-byte value
   - Attempted LoggerInfo decryption (both with CipheredPassword and DPAPI key)
   - **Result:** LoggerInfo has entropy 6.59-6.61, cannot unpad, likely still encrypted or wrong method

5. **SQLCipher database:** Tried all 31 DPAPI master keys, decrypted CipheredPassword, various KDFs
   - **Result:** Database remains locked

**Remaining Possibilities:**
- Meeting ID is only in the encrypted .zenc body or SQLCipher database
- Requires successful decryption of these files to extract
- May need user password (NT hash not crackable with standard wordlists)

### ❌ Flag 5: Meeting Duration
**Status:** FAILED - Cannot extract from encrypted sources

**Candidate Values Found in Memory:**
1. **180 seconds** (3 minutes) - 1 occurrence, no context
2. **1800 seconds** (30 minutes) - 1 occurrence, no context
3. **Fuzzy match:** Found "right/60/version" string in context, but no clear duration

**Attempted:**
Direct submission of candidates NOT attempted (no verification)

**Confidence Level:** VERY LOW
- No contextual evidence linking these to the actual meeting
- Without decrypting database/logs, cannot confirm which (if either) is correct
- Meeting could have been any length, these are just random finds

## Encryption Chain Analysis

### Successfully Decrypted (3 layers):
```
DPAPI Blob (Zoom.us.ini)
    ↓ dpapick3 + masterkey_at_2594413a.bin
    48-byte Zoom key ✓

CipheredPassword (.zenc header)
    ↓ AES-256-CBC with DPAPI key
    48-byte value ✓

LoggerInfo (.zenc header)
    ?? Encryption method unknown
    128 bytes (entropy: 6.59-6.61) ✗
```

### Cannot Decrypt (The BLOCKER):
```
.zenc Body (109,120 bytes)
    - Entropy: 7.9986 (perfect encryption)
    - Block aligned: 6820 blocks of 16 bytes
    - No PKCS7 padding (not AES-CBC)
    - Likely stream cipher or CTR mode
    - Unknown key derivation from LoggerInfo

zoomus.enc.db (SQLCipher)
    - Size: 110 KB
    - Header: Not standard SQLite
    - Tested: All 31 master keys, DPAPI key, PBKDF2 variants
    - Requires: Unknown password or key
```

## Tools and Methods Used

### Forensic Analysis:
- Volatility 3 (memory dump analysis)
- vshadowinfo (VSS timestamp extraction)
- File carving from disk image (image.001)

### Cryptographic Attempts:
- dpapick3 (DPAPI decryption) - ✓ SUCCESS
- AES-256-CBC (multiple layers) - ✓ PARTIAL SUCCESS
- ChaCha20, Salsa20, RC4 (stream ciphers) - ✗ FAILED
- PBKDF2, HKDF (key derivation) - ✗ FAILED
- zlib, gzip, bz2 (compression) - ✗ FAILED

### Pattern Analysis:
- Zoom meeting ID regex: [0-9]{9,11}
- Searched: memory, registry, browser history, cache files
- Result: No valid meeting IDs in plaintext

## Files Analyzed

**Evidence Recovered:**
- memory.raw (5 GB) - Analyzed for strings, registry, processes
- image.001 (2.1 GB) - Extracted VSS snapshot
- Volume Shadow Copy - Recovered deleted Zoom files
- NTUSER.DAT - Analyzed registry hive
- Edge_History, WebCacheV01.dat, ActivitiesCache.db - No meeting data
- zoom_memlog.zenc (109 KB) - Cannot decrypt body
- zoomus.enc.db (110 KB) - Cannot decrypt database
- Installer logs - No meeting information

**Decryption Artifacts:**
- 31 DPAPI master keys extracted from memory
- zoom_key_DECRYPTED.bin (48 bytes from DPAPI) ✓
- Decrypted CipheredPassword (48 bytes) ✓
- 2 variants of "decrypted" LoggerInfo (128 bytes) ✗

## Key Findings & Observations

1. **Strong Encryption:** The .zenc body has perfect entropy (7.9986) and no padding, indicating professional encryption implementation

2. **Multiple Layers:** The encryption chain is at least 4 layers deep (DPAPI → CipheredPassword → LoggerInfo → Body)

3. **Missing Link:** Cannot determine how LoggerInfo (128 bytes) derives the body encryption key

4. **Password Protected:** User NT hash not crackable (c8e9430ee9a1f04828e2214ed538c20b), likely strong password

5. **No Plaintext Leaks:** Meeting data never appears in memory or disk unencrypted

## Assumptions Made

1. Meeting ID format: 9-11 digits (standard Zoom format)
   - Could be wrong - maybe personal meeting ID (different format)

2. LoggerInfo decryption uses AES-256-CBC with CipheredPassword
   - Wrong? Maybe different cipher mode or algorithm entirely
   - LoggerInfo may not be decrypted correctly at all

3. .zenc body uses standard encryption
   - Wrong? Could be proprietary Zoom cipher
   - Could be compressed before encryption (still looks random)

4. Meeting duration is in seconds (as requested)
   - Correct assumption based on question format
   - Values found (180, 1800) may not be correct meeting duration

## What This Means

**Challenge Design:**
- Requires specialized knowledge of Zoom's proprietary .zenc format
- Or requires user password (not available)
- Or requires reverse engineering Zoom client binary
- "0 solves" confirms difficulty

**The encryption is correctly implemented:**
- Perfect entropy on encrypted data
- No implementation flaws or weaknesses found
- Standard forensic techniques insufficient

## Next Steps Recommendations

For future attempts, consider:

1. **Zoom Client Reverse Engineering**
   - Obtain Zoom.exe binary (version 6.3.0.52884)
   - Find encryption/decryption functions in binary
   - Understand proprietary key derivation

2. **Advanced Cryptanalysis**
   - Differential cryptanalysis on .zenc format
   - Known-plaintext attack (if structure known)
   - Side-channel analysis (if Zoom process available)

3. **Password Recovery**
   - More comprehensive hash cracking (rainbow tables)
   - Use found user info: username = a1l4m (Khalid)
   - Targeted wordlist generation based on persona

4. **Commercial Forensics Tools**
   - Magnet AXIOM (DPAPI support)
   - Passware Kit Forensic (SQLCipher support)
   - Elcomsoft tools (proprietary format decryption)

5. **Alternative Attack Vectors**
   - Check for Zoom CVEs/vulnerabilities
   - Look for configuration oversights
   - Memory timeline analysis (when was data encrypted?)

## Technical Notes

**Potentially Wrong Assumptions:**
- LoggerInfo decryption method (likely incorrect)
- .zenc body cipher mode (not AES-CBC, no padding)
- Key derivation from LoggerInfo to body key (unknown algorithm)
- Meeting ID format (could be non-standard)

**Unexplored Areas:**
- Full memory dump timeline analysis
- Zoom binary reverse engineering
- Network traffic capture (not available in evidence)
- LSA secrets from lsass.exe (may contain additional keys)

## Conclusion

This challenge demonstrates sophisticated encryption implementation by Zoom. After exhaustive analysis using standard forensic and cryptographic techniques, the meeting data remains inaccessible. Success requires either:

1. Zoom proprietary encryption knowledge
2. User password recovery
3. Reverse engineering capabilities
4. Advanced cryptanalytic techniques

**Status: BLOCKED AT ENCRYPTION LAYER**

The first 3 flags were solved through standard forensics. Flags 4 and 5 require specialized knowledge or tools beyond standard CTF cryptographic techniques.
