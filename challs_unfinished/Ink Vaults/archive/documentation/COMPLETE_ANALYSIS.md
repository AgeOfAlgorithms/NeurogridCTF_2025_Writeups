# Ink Vaults - Complete Analysis & Current Status

## 🏁 Challenge Overview

**Challenge**: Ink Vaults (HackTheBox CTF - Neurogrid 2025)
**Category**: Web/Steganography/MCP
**Status**: **IN PROGRESS** - PGP keys extracted, awaiting transformation
**Container**: 154.57.164.77:30826
**Goal**: Unlock scroll 7 "The Final Stroke" to reveal the flag

---

## ✅ Completed Discoveries

### 1. Terminating Stroke Character ✓
- **Character**: 靑 (U+9751, Chinese character "blue/green")
- **Location**: Extracted from scroll_7.png via steganography
- **Purpose**: Breaks Archivist AI recursion loop, triggers Chinese response
- **Found**: In scroll_7.png bit plane b2,b,msb (confirmed by manual extraction)

### 2. MCP Tool Architecture ✓
**Three tools available:**
- `list_scrolls` - Lists all temple scrolls
- `archivist_query_sql` - Executes SELECT queries
- `guardian_query_sql` - Executes SELECT and UPDATE queries (REQUIRES AUTH)

**Authentication**: Bearer token required for tool execution (not just listing)

### 3. JavaScript Analysis ✓
**Files analyzed:**
- `archivist_page.js` - Main UI (26.5KB)
- `*_app*.js` - Next.js framework files
- `page-*.js` - Page components

**Findings:**
- Hardcoded JWT tokens found (admin role)
- Admin token tested: **DOES NOT WORK** for guardian auth
- Flag mechanism: Scroll objects have `flag` property set when availability="Available"
- Hint text in JavaScript references "second layer of protection" and "hidden trigger"

### 4. PGP Secret Key Discovery ✓
**Major breakthrough using zsteg!**

**Scroll 7 contains:**
- OpenPGP Secret Key at bit plane **b2,b,msb**
- PGP Secret Sub-keys at **b1,r,lsb,Yx,prime** and **b3p,r,msb,Yx**

**Extraction details:**
- Method: Extract bit 2 from blue channel, MSB ordering
- Output: 131,072 bytes (1,048,576 bits)
- Contains valid PGP packet magic bytes (0x99, 0x95, 0x88, etc.)

### 5. PGP Key Analysis ✓
**Status: CORRUPTED/OBFUSCATED**

**What we found:**
- 113 instances of packet tag 0x99 (Public Key)
- 82 instances of packet tag 0x95 (Private Key)
- 47 instances of packet tag 0x88 (Compressed Data)
- All packets have malformed content
- Invalid packet versions (e.g., version 255)
- Length fields inconsistent

**Commands used:**
```bash
zsteg scroll_7.png  # Found "OpenPGP Secret Key"
gpg --list-packets pgp_extract_99_978.bin  # Shows corrupted packets
```

---

## 🔒 Current Blocker: PGP Key Obfuscation

The guardian authentication token is **hidden inside the corrupted PGP keys**.

### The "Clapper-Less Bell" Hint
Original challenge hints mention:
- "clapper-less bell"
- "sequence 07"
- "terminating stroke"

**Interpretation:** The PGP keys require transformation/decryption using:
- XOR with bell character (ASCII 7 = 0x07)
- XOR with "07" sequence
- XOR with terminating stroke 靑
- Some combination of the above

### What Doesn't Work
- ❌ Admin JWT token from JavaScript
- ❌ Terminating stroke as bearer token
- ❌ Direct tool execution (always returns "Authentication required")
- ❌ Uncorrupted PGP keys (they won't import with gpg)

---

## 🎯 Recovery Strategy

### Step 1: Transform PGP Keys
Extract authentication token by trying:
```python
# XOR with bell (ASCII 7)
xored = bytes(b ^ 0x07 for b in pgp_data)

# XOR with "07"
xor_07 = bytes(b ^ 0x30 ^ 0x37 for b in pgp_data)

# XOR with terminating stroke
靑_val = int.from_bytes('靑'.encode('utf-8'), 'big')
xored_靑 = bytes(b ^ (靑_val & 0xFF) for b in pgp_data)
```

### Step 2: Search for JWT Pattern
In transformed data, look for:
- `eyJ` (JWT header start)
- ASCII-armored PGP blocks
- Plaintext secrets

### Step 3: Use Auth Token
Once found, update MCP config and execute:
```bash
curl -X POST "http://154.57.164.77:30826/mcp" \
  -H "Authorization: Bearer <FOUND_TOKEN>" \
  -d '{"method":"tools/call","params":{"name":"guardian_query_sql","arguments":{"query":"UPDATE scrolls SET scroll_availability = '"'"'Available'"'"' WHERE id = 7"}}}'
```

### Step 4: Retrieve Flag
Once update succeeds, flag appears in scroll 7 data.

---

## 📁 File Organization

```
Ink Vaults/
├── scroll_1.png through scroll_7.png  # Source images
├── scripts/                            # Python/bash scripts
│   ├── extract_bit_planes.py
│   ├── pgp_key_recovery.py
│   ├── exploit_final.py
│   └── mcp_vuln_test_curl.sh
├── analysis_files/
│   ├── extracted_data/                 # All bit plane extractions
│   ├── extracted_keys/                 # PGP key fragments
│   └── js_analysis/                    # JavaScript source files
├── documentation/                      # All markdown docs
│   ├── BLOCKERS.md                     # Historical blockers
│   ├── PGP_KEYS_FINDINGS.md           # This discovery
│   ├── SOLUTION.md                     # Initial (incorrect) solution
│   └── TOKEN_DISCOVERY.md             # Admin token findings
└── old_attempts/                       # Stale files
```

---

## 🔑 Key Data

### Terminating Stroke
- Character: 靑
- Unicode: U+9751
- UTF-8: e9 9d 91

### Admin Token (Invalid for guardian)
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwidXNlcm5hbWUiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImVtYWlsIjoidGVzdEB0ZXN0LmNvbSIsImlhdCI6MTc2MzY3MzU3OCwiZXhwIjoxNzYzNjc3MTc4LCJqdGkiOiJmb3JnZWQtYWRtaW4tdG9rZW4tMDAxIn0.8BP6OaQSuOOKO0HMv4wAhwR8_22kfL7f6FKzVISxYgk
```

### MCP Configuration
```json
{
  "type": "sse",
  "url": "http://154.57.164.77:30826/mcp",
  "headers": {
    "Authorization": "Bearer eyJ...admin_token..."
  }
}
```

### Extracted PGP Key Location
```
analysis_files/extracted_keys/potential_pgp_key.bin
```

---

## 📝 Next Actions Priority

1. **URGENT**: Try XOR transformations on PGP data (bell, 07, 靑)
2. Test each transformation for JWT pattern
3. Once token found, update MCP config and restart Claude Code
4. Run final exploit to unlock scroll 7
5. Capture the flag

---

## 💡 Lessons Learned

1. **Don't trust client-side tokens**: Admin JWT from JavaScript didn't work
2. **Check all bit planes**: PGP keys hidden in non-obvious planes
3. **Use zsteg**: Manual extraction missed the PGP markers
4. **Challenge hints are literal**: "clapper-less bell" = XOR with 0x07
5. **Data is obfuscated**: Keys must be transformed before use

---

**Last Updated**: 2025-11-23
**Status**: Ready for PGP transformation tests
**Blocker**: Guardian auth bypass via PGP key transformation
