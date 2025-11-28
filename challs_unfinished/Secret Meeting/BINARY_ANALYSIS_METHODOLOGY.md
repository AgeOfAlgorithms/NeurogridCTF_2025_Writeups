# Zoom.exe Binary Analysis Methodology
**For Secret Meeting CTF (Windows Environment)**

---

## Overview
This document outlines the reverse engineering approach to extract Zoom's .zenc encryption algorithm and keys from the Zoom.exe binary. This is the most viable path to solving flags 4 and 5.

---

## Phase 1: Static Analysis (Initial Recon)

### Required Tools
- IDA Pro or Ghidra (disassembler/decompiler)
- x64dbg (debugger)
- Process Monitor (ProcMon)
- Strings utility
- dumpbin (part of Visual Studio)

### Commands and Steps

#### 1.1 Basic File Analysis
```bash
# Verify Zoom version (match installer.txt: 6.3.0.52884)
sigcheck.exe -a zoom.exe

# Examine PE structure
dumpbin.exe /headers zoom.exe

# Identify imported DLLs and crypto APIs
dumpbin.exe /imports zoom.exe | findstr /i "crypt bcrypt rsa aes ssl"

# List exported functions
dumpbin.exe /exports zoom.exe
```

#### 1.2 String Extraction (Critical First Step)
```bash
# Extract all strings 8+ characters
strings.exe -n 8 zoom.exe > zoom_strings.txt

# Filter for encryption-related strings
strings.exe -n 8 zoom.exe | findstr /i "zenc encrypt decrypt cipher AES ChaCha20 Salsa20 RC4 logger"

# Filter for file operation strings
strings.exe -n 8 zoom.exe | findstr /i ".zenc CreateFile ReadFile WriteFile"

# Filter for error messages
strings.exe -n 8 zoom.exe | findstr /i "failed invalid decrypt error"
```

**Key Strings to Locate:**
- `"ReceiverVersion"`, `"LoggerInfo"`, `"CipheredPassword"` (header fields)
- `"AES"`, `"ChaCha20"`, `"Salsa20"` (algorithm names)
- `"failed to decrypt"`, `"invalid logger"` (error messages)
- `"\.zenc"`, `"zoomus.enc.db"` (file paths)
- Base64 patterns, magic constants

#### 1.3 Identify Crypto Libraries
Look for imports of:
- `bcrypt.dll` (Windows CNG)
- `rsaenh.dll` (CAPI)
- `libeay32.dll` / `ssleay32.dll` (OpenSSL)
- Static linking (no imports = custom implementation)

---

## Phase 2: Dynamic Analysis (Runtime Behavior)

### 2.1 File I/O Monitoring with ProcMon
```bash
# Launch ProcMon with filters
procmon.exe /AcceptEula /Quiet /Minimized /BackingFile zoom.pml

# Filters to apply in ProcMon GUI:
# - Process Name contains "zoom"
# - Operation is "CreateFile"
# - Path contains ".zenc"
```

**What to observe:**
- When Zoom opens .zenc files (path, timestamp)
- File access mode (read/write)
- Subsequent ReadFile operations (size, offset)
- Thread IDs (correlate with debugger)

### 2.2 Attach Debugger
```bash
# Launch Zoom under x64dbg
x64dbg.exe zoom.exe

# Or attach to running process
x64dbg.exe -p <PID>
```

**Initial breakpoints:**
- `CreateFileA` / `CreateFileW` (capture .zenc file handle)
- `ReadFile` (capture encrypted data)
- `CryptDecrypt` / `BCryptDecrypt` (if using Windows APIs)

### 2.3 Memory Layout Analysis
```bash
# In x64dbg, examine memory maps
# Look for:
# - Allocations matching .zenc file size (109 KB)
# - LoggerInfo data (128 bytes from header)
# - Key material (32-48 byte buffers)
```

---

## Phase 3: Code Reverse Engineering

### 3.1 Locate Key Functions

**Using IDA Pro/Ghidra:**

1. **Find LoggerInfo Parsing:**
```c
// Search for "LoggerInfo" string reference
// Should lead to code like:
char* parse_logger_info(char* header) {
    char* start = strstr(header, "LoggerInfo:");
    if (!start) return NULL;
    start += 11; // Skip "LoggerInfo:"
    // Base64 decode
    // Return 128 bytes
}
```

2. **Find CipheredPassword Decryption:**
```c
// Trace backward from LoggerInfo usage
// Should find:
void decrypt_ciphered_password(uint8_t* dpapi_blob, uint8_t* output_48bytes) {
    // DPAPI decryption
    // Output: 48 bytes
}
```

3. **Find LoggerInfo Decryption:**
```c
// Two possibilities:
// A) Uses CipheredPassword result as key
void decrypt_logger_info(uint8_t* encrypted_logger, uint8_t* key48, uint8_t* output_128) {
    // AES-256-CBC with:
    // Key = key48[0:32]
    // IV  = key48[32:48]
}

// B) Uses DPAPI key directly
void decrypt_logger_info_alt(uint8_t* encrypted_logger, uint8_t* dpapi_key48, uint8_t* output_128) {
    // Different algorithm
}
```

4. **Find Key Derivation Function (CRITICAL):**
```c
// This is the missing link
void derive_body_key(uint8_t* logger_info_128, uint8_t* salt, uint8_t* output_key) {
    // Likely candidates:
    // - PBKDF2-HMAC-SHA256(logger_info, salt, iterations)
    // - HKDF(logger_info, salt)
    // - Custom KDF (hash chains, XOR patterns)
    // - ChaCha20 key setup (if stream cipher)
}
```

5. **Find Body Decryption:**
```c
void decrypt_log_body(
    uint8_t* encrypted_body,  // 109120 bytes
    size_t body_len,
    uint8_t* derived_key,     // Likely 32 bytes
    uint8_t* nonce,           // Likely 12 bytes (ChaCha20) or 16 bytes (AES-CTR)
    uint8_t* output_plaintext
) {
    // Likely ChaCha20 or AES-CTR (no padding observed)
}
```

### 3.2 Identify Encryption Algorithm

**ChaCha20 Indicators:**
```assembly
; Look for quarter-round operations:
movdqa  xmm0, [key]
movdqa  xmm1, [counter]
paddd   xmm1, [one]      ; Counter increment
... 10+ rounds of quarter-round ...
pxor    [plaintext], xmm0 ; XOR keystream
```

**AES-CTR Indicators:**
```assembly
; Look for:
call    encrypt_ctr_block
mov     esi, ciphertext
xor     [plaintext], eax  ; XOR with AES output
```

**Custom Algorithm:**
- Hardcoded S-boxes
- Unusual permutation tables
- Non-standard round structure

### 3.3 Extract Constants

**Look for:**
- Key derivation iterations count (likely 10,000-100,000)
- Salt strings (maybe "ReceiverVersion", "V01", "Zoom")
- Magic numbers in bit operations
- Lookup tables (S-boxes, constants)

---

## Phase 4: Dynamic Key Extraction

### 4.1 Frida Instrumentation Script

```javascript
// Frida script to hook decryption functions

// Attach to Zoom process
const session = await frida.attach('zoom.exe');

// Find base address
const baseAddr = Module.findBaseAddress('zoom.exe');

// Hook CreateFileA to find .zenc file operations
Interceptor.attach(Module.findExportByName('kernel32.dll', 'CreateFileA'), {
    onEnter: function(args) {
        const filename = args[0].readUtf8String();
        if (filename.includes('.zenc')) {
            console.log('[*] Opening .zenc file:', filename);
            this.isZenc = true;
        }
    },
    onLeave: function(retval) {
        if (this.isZenc) {
            console.log('    Handle:', retval);
            this.fileHandle = retval;
        }
    }
});

// Hook ReadFile to capture data
Interceptor.attach(Module.findExportByName('kernel32.dll', 'ReadFile'), {
    onEnter: function(args) {
        if (args[0].equals(this.fileHandle)) {
            this.buffer = args[1];
            this.size = args[2].toInt32();
        }
    },
    onLeave: function() {
        if (this.buffer) {
            console.log('[*] Read', this.size, 'bytes:');
            console.log(hexdump(this.buffer, {length: Math.min(this.size, 64)}));
        }
    }
});

// Find decryption function by scanning for LoggerInfo string
const loggerInfoStr = Memory.scanSync(baseAddr, 0x1000000, '4c 6f 67 67 65 72 49 6e 66 6f'); // "LoggerInfo"
if (loggerInfoStr.length > 0) {
    console.log('Found LoggerInfo reference at:', loggerInfoStr[0].address);
    // Set breakpoint near this address
}

// Hook candidate decryption function
const decryptAddr = baseAddr.add(0xOFFSET); // Found via disassembly
Interceptor.attach(decryptAddr, {
    onEnter: function(args) {
        console.log('[*] Decryption function called');
        console.log('Input buffer:', hexdump(ptr(args[0]), {length: 64}));
        console.log('Key buffer:', hexdump(ptr(args[1]), {length: 48}));
        this.output = args[2];
    },
    onLeave: function() {
        console.log('Output buffer:', hexdump(this.output, {length: 128}));
    }
});
```

### 4.2 Memory Scanning with Cheat Engine

```
1. Launch Zoom and let it load .zenc file
2. Open Cheat Engine, attach to zoom.exe
3. Scan for known values:
   - LoggerInfo base64 string (BAGIZu...)
   - Decrypted LoggerInfo (if in memory)
4. Find what accesses this address
5. Trace back to decryption function
```

### 4.3 Dump Keys from Memory

```javascript
// Once decryption function is identified:
Interceptor.attach(decryptLoggerInfo, {
    onLeave: function() {
        // Dump the "decrypted" LoggerInfo (128 bytes)
        const loggerInfo = ptr(this.context.rax); // Return value
        const data = loggerInfo.readByteArray(128);
        console.log('LoggerInfo (hex):', hexdump(data));

        // Also dump the key if passed in arguments
        const keyPtr = ptr(this.context.rdx);
        const key = keyPtr.readByteArray(48);
        console.log('Key material (hex):', hexdump(key));
    }
});
```

---

## Phase 5: Replicate Decryption

### 5.1 Extract Algorithm Parameters

From analysis, document:
```
Algorithm: [ChaCha20 / AES-CTR / Custom]
Key size: [32 bytes / 16 bytes]
Nonce/IV size: [12 bytes / 16 bytes]
Key derivation: [PBKDF2 iterations / HKDF / None]
Salt: [string value]
```

### 5.2 Python Implementation

```python
# Once parameters are known, implement in Python

def decrypt_zenc_body(encrypted_body, logger_info):
    """Decrypt .zenc body using extracted algorithm"""

    # Step 1: Derive key from LoggerInfo
    if KDF == "PBKDF2":
        key = PBKDF2(logger_info[:32], salt=b"V01", iterations=10000, dklen=32)
        nonce = PBKDF2(logger_info[32:], salt=b"V01", iterations=10000, dklen=12)
    elif KDF == "direct":
        key = logger_info[:32]
        nonce = logger_info[32:44]

    # Step 2: Decrypt based on algorithm
    if algorithm == "ChaCha20":
        cipher = ChaCha20.new(key=key, nonce=nonce)
        plaintext = cipher.decrypt(encrypted_body)
    elif algorithm == "AES-CTR":
        cipher = AES.new(key=key, mode=AES.MODE_CTR, nonce=nonce)
        plaintext = cipher.decrypt(encrypted_body)

    return plaintext

# Apply to our .zenc file
with open('zoom_memlog.zenc', 'rb') as f:
    data = f.read()

header_end = data.find(b'End\n') + 4
body = data[header_end:]

with open('decrypted_loggerinfo.bin', 'rb') as f:
    logger_info = f.read()

plaintext = decrypt_zenc_body(body, logger_info)

# Check if successful
if plaintext.startswith(b'2025') or plaintext.startswith(b'Zoom'):
    print("Success! Decrypted log:")
    print(plaintext[:500])
else:
    print("Decryption failed - wrong algorithm or key")
```

---

## Expected Timeline

### Realistic Estimates:

| Phase | Task | Time |
|-------|------|------|
| 1 | String extraction & initial analysis | 30 min |
| 2 | ProcMon + debugger setup | 1 hour |
| 3 | Finding decryption functions | 2-6 hours |
| 4 | Understanding key derivation | 2-4 hours |
| 5 | Replicating decryption in Python | 1 hour |
| **Total** | | **6-12 hours** |

**Best case:** 6 hours (if ChaCha20 with simple KDF)
**Worst case:** 20+ hours (if custom cipher, obfuscated, anti-debugging)

---

## Success Indicators

### You're on right track when:
- ✅ Find "LoggerInfo" string reference in disassembly
- ✅ Identify `CreateFileA` call with `.zenc` path
- ✅ Dump decrypted LoggerInfo that looks like structured data
- ✅ Find function that takes 128 bytes → outputs 32/12 bytes
- ✅ Identify ChaCha20 quarter-round or AES-CTR patterns
- ✅ Successfully decrypt first 100 bytes to readable log format

### Red flags (going wrong):
- ❌ No crypto imports (might be statically linked)
- ❌ Heavy obfuscation (VMProtect, Themida)
- ❌ Anti-debugging tricks (crash, exit on attach)
- ❌ LoggerInfo not in memory (processed differently)
- ❌ Multiple layers of encryption

---

## Alternative Approaches

### If standard RE fails:

**1. API Hooking without Debugger:**
```c
// Use Microsoft Detours library
DetourAttach(&(PVOID&)Real_CreateFileA, Mine_CreateFileA);
// Log all file operations without triggering anti-debug
```

**2. Kernel Debugging:**
```bash
# Use WinDbg kernel mode to bypass userland anti-debug
# More complex but harder to detect
```

**3. Emulation:**
```python
# Use Unicorn engine to emulate decryption function
# Feed it our LoggerInfo, capture output
```

**4. GPU-assisted cracking:**
```bash
# If key derivation is PBKDF2 with low iterations
# Try hashcat with extracted salt
hashcat -m 10000 -a 3 zoom_key.hccapx ?a?a?a?a?a?a?a?a
```

---

## Deliverables

Once completed, capture:

1. **Decryption algorithm name** (ChaCha20, AES-CTR, etc.)
2. **Key derivation method** (PBKDF2 iterations, salt)
3. **Sample decrypted log** (first 200 bytes)
4. **Meeting ID** (from decrypted log)
5. **Meeting duration** (from decrypted log)
6. **Python decryption script** (for documentation)

---

## Tool Installation (Windows)

```powershell
# IDA Pro (commercial)
# https://www.hex-rays.com/ida-pro/

# Ghidra (free)
# https://github.com/NationalSecurityAgency/ghidra

# x64dbg (free)
# https://x64dbg.com/

# Sysinternals Suite (free)
# https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite

# Frida (Python)
pip install frida frida-tools

# Capstone (disassembly engine for Python)
pip install capstone
```

---

**Author:** CTF Investigation Team
**Date:** 2025-11-23
**Target:** Zoom 6.3.0.52884 (from installer logs)
**Challenge:** Secret Meeting (HackTheBox Neurogrid CTF)
