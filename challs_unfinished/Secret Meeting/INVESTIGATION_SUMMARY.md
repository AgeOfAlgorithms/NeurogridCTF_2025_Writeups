# Secret Meeting CTF - Investigation Summary
## Last Updated: 2025-11-23

## Challenge Details
- **Name:** Secret Meeting
- **Category:** Forensics
- **Difficulty:** Hard (1000 points)
- **Solves:** 0
- **Files:** memory.raw (5GB), image.001 (2.1GB NTFS disk image)

## Flags Status: 3/5 SOLVED

### ✅ Solved Flags

**Flag 1: Installation Timestamp**
- **Answer:** `2024-12-17 08:51:01`
- **Method:** Volatility windows.registry.userassist on memory.raw
- **Location:** User assist registry key containing Zoom installation timestamp

**Flag 2: Deletion Tool**
- **Answer:** `SDelete`
- **Method:** Volatility windows.strings + grep on memory.raw
- **Finding:** 624 occurrences of "SDelete" string confirming secure deletion tool

**Flag 3: Snapshot Timestamp**
- **Answer:** `2025-03-06 17:17:33`
- **Method:** Volume Shadow Copy (VSS) metadata analysis in image.001
- **Location:** Shadow copy creation timestamp

### ❌ Blocked Flags

**Flag 4: Meeting ID** - UNSOLVED
**Flag 5: Meeting Duration** - UNSOLVED

**Blocker:** Cannot extract meeting data from encrypted sources

## Evidence Files

**Primary Sources:**
- `memory.raw` (5GB) - Windows memory dump
- `image.001` (2.1GB) - NTFS disk image with VSS snapshot

**Key Files Extracted from VSS:**
- `Zoom.us.ini` - Contains DPAPI-encrypted database key
- `zoom_memlog_3376_20250306-172649.log.zenc` - Encrypted log file
- `zoomus.enc.db` (112KB) - SQLCipher encrypted database
- `viper.ini` - Device configuration (VMware network adapter info)
- `client.config` - Zoom client settings
- `installer.txt` - Installation logs

**User Account:**
- Username: `a1l4m` (Khalid)
- SID: S-1-5-21-593536282-824182100-2440914132-1000
- NT Hash: `c8e9430ee9a1f04828e2214ed538c20b` (not crackable)

## Encryption Chain Analysis

### Successfully Decrypted:

**1. DPAPI Blob (Zoom.us.ini → SQLCipher Key)**
```
Input: 262-byte DPAPI blob from Zoom.us.ini
  win_osencrypt_key=ZWOSKEY[base64]

Decryption: Used 31 extracted master keys from memory.raw
  Master Key GUID: d2e8e6c0-b196-48ce-b4f3-60a4c99ab7f4

Output: 48-byte value
  1ce9ff4c9a63252a11a09e9b04dbaf10c28d604f06df3bc2017818370809b3678cd13436ee958a7f1e41d5cf70f7e5da

Saved as: zoom_key_DECRYPTED.bin
```

**2. CipheredPassword (.zenc file → Unknown)**
```
Input: 48-byte CipheredPassword from .zenc file
  834b7925662c9a8f749a96e6f1b16e0a1ff76e7a1d5ab2bb851a3f770662d453a7381ed5d7f8661586f14d528e5ea41a

Decryption: AES-256-CBC using DPAPI decrypted key
  Key: First 32 bytes of zoom_key_DECRYPTED.bin
  IV: Last 16 bytes of zoom_key_DECRYPTED.bin

Output: 48-byte value
  4d255115e9dd08935374e77753997cb958d68e6ed56992c638ed9772edae2e1d4d241f095c1897364ddb9b8f91a8bf47
```

### Failed Decryption Attempts:

**3. LoggerInfo (.zenc file) - FAILED**
```
Structure:
  ReceiverVersion:V01
  CipheredPassword: [48 bytes, successfully decrypted above]
  CipherSignature: [RSA signature, 136 bytes]
  LoggerInfo: [133 bytes base64-encoded]

Attempts:
  - AES-256-CBC with decrypted CipheredPassword as key/IV
  - AES-256-CBC with DPAPI decrypted key as key/IV
  - Tried skipping 0-8 byte headers
  - All attempts produce random-looking bytes, no readable text

Status: Incorrect decryption method or missing key
```

**4. SQLCipher Database (zoomus.enc.db) - FAILED**
```
Database: 112KB SQLCipher encrypted database
Header: Not standard SQLite (starts with 0abe00a9b4e43017)

Attempts:
  - All 31 DPAPI-decrypted master keys
  - Decrypted CipheredPassword value
  - Different SQLCipher parameters (kdf_iter: 4000, 64000, 256000)
  - Different cipher_page_size values
  - SHA256 hashes of keys
  - PBKDF2 derivations
  - Various key length combinations (32 bytes, 48 bytes, chunks)

Result: Database remains locked
Status: Likely requires password-derived key
```

## Attempts to Find Password

### 1. Hash Cracking - FAILED
- NT Hash: `c8e9430ee9a1f04828e2214ed538c20b`
- Online databases: Not found (CrackStation, etc.)
- Rockyou.txt: Exhausted in 1 second, 0 recovered
- Targeted wordlists: 63 CTF-themed + 46 user-themed passwords - no matches
- Brute force: Numeric (1-6 digits), lowercase (1-4 letters) - no matches

### 2. Memory Forensics - FAILED
- Plaintext password search: 0 matches for "password", "passwd", "a1l4m"
- DPAPI master key search: Found 13 GUID occurrences, extracted 31 keys, none decrypted database
- SQLCipher key search: 0 hex patterns near "sqlcipher" keyword

### 3. Alternative Meeting ID Sources - FAILED
**Tested and Wrong:**
- `3386965317` from viper.ini (actually hex-encoded device ID)
- `20417564696` from viper.ini hex strings
- `20446576696` from viper.ini hex strings

**Search Results:**
- No 10-11 digit meeting IDs in plaintext anywhere in memory.raw
- No meeting IDs in unencrypted configuration files
- Meeting data confirmed to be only in encrypted database/logs

## .zenc File Structure

**Header Fields:**
```
ReceiverVersion:V01
CipheredPassword:g0t5JWYsmo90mpbm8bFuCh/3bnodWrK7hRo/dwZi1FOnOB7V1/hmFYbxTVKOXqQa
CipherSignature:MIGIAkIA1BsJQIfYW6gyrnXKQkWTHumZstuD73kmwEYbU4OxYlNi6jHsGnABUFMLtaDxqP1jDkjZE3KUsmO4BX69RPeeqGkCQgCi/MhZSgzuaGab3j/Fvkz+ub4OQCD3/imekhvFmROq4RurxIttE1qJlIT4KR1OJe6NCSlF68CeD/zFwcwT4Gv1ww==
LoggerInfo:BAGIZuMUPdFUV7CmGFkHybF9O+L0zoOMzeC9oruv2nMi76fI3gB9cl2C2cYTNONYoGBb+9lCMqkKAtRuZfB7xKPsFgABQDPU2CD7tytSz/fQvM+MamZD60cbPA2zoSRVZZxbyPtijV59/jH5Vu+eUGqnbZkleBIEWRBhOyDxD8vs2Lw2lg==
End
[109KB of encrypted log data]
```

**LoggerInfo Analysis:**
- Base64 decoded: 133 bytes
- Valid AES block size: 128 bytes (skipping 5-byte header)
- Decryption produces random bytes with both attempted keys
- **Hypothesis:** Different encryption scheme, compressed, or requires different key derivation

## Tools Used

**Forensics:**
- Volatility 3 - Memory analysis
- 7-Zip/fls/icat - File extraction from disk image
- Volatility windows.registry.userassist - Registry analysis
- Volatility windows.strings - String extraction

**Cryptography:**
- dpapick3 - DPAPI blob decryption
- PyCryptodome - AES encryption/decryption
- hashcat - Password cracking attempts
- SQLCipher - Database access attempts

## Key Findings

1. **DPAPI Master Keys Successfully Extracted:** 31 master keys from memory successfully decrypt the DPAPI blob
2. **CipheredPassword Successfully Decrypted:** Using AES-256-CBC with DPAPI key
3. **LoggerInfo Encryption Unknown:** Standard AES-CBC doesn't produce readable output
4. **SQLCipher Database Locked:** No extracted/derived keys unlock the database
5. **Password Not Crackable:** Strong password not in any wordlist or brute-forceable range
6. **No Plaintext Leaks:** Meeting ID not found anywhere unencrypted in memory or disk

## Unanswered Questions

1. **What is the correct method to decrypt LoggerInfo?**
   - Is it compressed (zlib/gzip)?
   - Does it use a different encryption algorithm?
   - Is there a key derivation step we're missing?

2. **What unlocks the SQLCipher database?**
   - Password-derived key using PBKDF2?
   - Different key from what we've tried?
   - Alternative decryption in Zoom client code?

3. **Where is the meeting data actually stored?**
   - Only in encrypted database?
   - Could be in the encrypted portion of .zenc file?
   - Windows registry or other location?

4. **What is the CipheredPassword used for?**
   - We decrypted it but don't know its purpose
   - Not the SQLCipher key
   - Not the LoggerInfo decryption key (as attempted)

## Next Steps for Investigation

1. **Analyze Zoom Client Binary:**
   - Reverse engineer encryption/decryption routines
   - Find key derivation functions
   - Understand .zenc file format completely

2. **Try Alternative Decryption Methods:**
   - Test compression algorithms on LoggerInfo
   - Try other cipher modes (ECB, CTR, GCM)
   - Check if RSA CipherSignature is involved

3. **Search for Additional Key Material:**
   - Check if there are other configuration files
   - Look for hardcoded keys in Zoom binaries
   - Examine memory for decrypted keys during runtime

4. **Consider Challenge Design:**
   - May require information not in forensic evidence
   - Possible vulnerability in Zoom's encryption implementation
   - CTF-specific backdoor or weakness

## Files to Preserve

**Essential Evidence:**
- memory.raw
- image.001
- Zoom.us.ini
- zoom_memlog_3376_20250306-172649.log.zenc
- zoomus.enc.db

**Successful Decryptions:**
- zoom_key_DECRYPTED.bin (48 bytes from DPAPI)
- All masterkey_at_*.bin files (31 master keys)

**Useful Scripts:**
- decrypt_dpapi.py (DPAPI blob decryption)
- run_dpapi_decrypt.py (working DPAPI decryption)

## Conclusion

This challenge requires either:
1. **Finding an alternative decryption method** for LoggerInfo or SQLCipher database
2. **Discovering the user's password** through an undiscovered clue
3. **Reverse engineering Zoom client** to understand proprietary encryption
4. **Finding meeting data in an unexpected location** we haven't searched yet

The encryption chain is partially solved but the final step to extract meeting ID and duration remains blocked. The challenge has 0 solves, indicating it's either very difficult or requires specialized knowledge/tools.
