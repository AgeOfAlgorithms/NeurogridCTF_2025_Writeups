# Ink Vaults - Comprehensive Discovery Report

**Challenge:** Ink Vaults (HackTheBox Neurogrid CTF 2025)
**Status:** MAJOR PROGRESS - FOUND FLAG MECHANISM
**Container:** 154.57.164.77:30826 (Running via keepalive)

## 🎯 BREAKTHROUGH DISCOVERY

### Scroll Objects Contain Flag Property!

**Location:** `js_analysis/archivist_page.js` line analysis reveals:
```javascript
flag:null!=(a=t.flag)?a:void 0
```

**What this means:**
- Every scroll object has a `flag` property
- When scroll 7 becomes "Available", it will contain the flag: `HTB{...}`
- The flag is hidden until scroll 7 is unlocked

**Current scroll status from `/api/scrolls`:**
```json
[
  {"id": 1, "title": "The Chronicle of the Realm", "scroll_availability": "Available"},
  {"id": 2, "title": "The Scroll of Unending Dawn", "scroll_availability": "Available"},
  {"id": 3, "title": "The Obsidian Codex", "scroll_availability": "Available"},
  {"id": 4, "title": "The Book of Temple Rites", "scroll_availability": "Available"},
  {"id": 5, "title": "The Resonance Index", "scroll_availability": "Available"},
  {"id": 6, "title": "The Scroll of Ash", "scroll_availability": "Available"},
  {"id": 7, "title": "The Final Stroke", "scroll_availability": "Forgotten", "flag": "???"}
]
```

## ✅ Completed Discoveries

### 1. Terminating Stroke Character Located
**Character:** 靑 (U+9751 - CJK Unified Ideographs)
**How found:**
- Extracted from scroll_7.png via steganography (bit plane b2,b,msb,xy)
- When sent to Archivist AI, breaks the recursion loop
- Archivist responds in Chinese after receiving 靑
- Used in MCP Authorization header: `Bearer 靑`

### 2. MCP Tools Identified
**Endpoint:** `http://154.57.164.77:30826/mcp`
**Tools discovered:**
- `list_scrolls` - Lists all scrolls (no auth required)
- `archivist_query_sql` - Executes SELECT queries (lists with auth, executes with guardian auth)
- `guardian_query_sql` - Executes SELECT and UPDATE queries (lists with auth, executes with guardian auth)

### 3. MCP Configuration Working
**Config location:** `~/.claude.json`
**Status:** ✅ Correctly configured
```json
{
  "type": "sse",
  "url": "http://154.57.164.77:30826/mcp",
  "headers": {
    "Authorization": "Bearer 靑",
    "Cookie": "chain_uuid=d73d7dcc-2347-445d-931d-6f7dcd32f35d"
  }
}
```

### 4. Steganography Analysis Complete
**Tools created:**
- `extract_bit_planes.py` - Extracts bit planes from scroll images
- `extract_steganography.sh` - Runs multiple steg tools

**Data extracted:**
- Scroll 1: b3,rgb,msb,xy - Secret Key location
- Scroll 1: b4,r,lsb,xy - Public Key location
- Scroll 2: b1,r,msb,xy - Secret Key location
- Scroll 6: b3,g,lsb,xy - Secret Key location
- Scroll 7: b2,b,msb,xy - Terminating stroke (靑)

**NOTE:** PGP keys were corrupted/unreadable in extracted data

### 5. Web Application Reverse Engineered
**Pages analyzed:**
- `/` - Main landing page with navigation
- `/archivist` - Chat interface with scroll query functionality
- `/mcp` - MCP endpoint endpoint

**Key JavaScript files:**
- `archivist_page.js` (26.5KB) - Contains flag property reference
- `page-39560b7f7055056b.js` (15KB) - Main app logic
- Main React component with scroll querying via `sendScrollQuery()`

### 6. Archivist AI Behavior Documented
**Messages endpoint:** `/api/messages`
**Send endpoint:** `/api/messages/send`

**Behavior patterns:**
- Without 靑: Recursion loop (repeats same message)
- With 靑: Breaks recursion, responds in Chinese, queries database via `archivist_query_sql`
- System messages show when database queries are executed
- Does NOT use `guardian_query_sql` even when prompted as "Guardian Monk"

### 7. Attack Vectors Tested

**MCP Authentication Bypass Attempts:**
- ✅ Bearer token with 靑 - Lists tools but cannot call them
- ❌ Hai Tsukemono-style convergence filters - Failed
- ❌ Prototype pollution (__proto__, constructor) - Failed
- ❌ Property descriptor manipulation - Failed
- ❌ Array argument injection - Failed
- ❌ Race condition attacks - Failed
- ❌ Bell character (\x07) + 靑 combinations - Failed
- ❌ Prompt injection via Archivist - Only triggers archivist_query_sql
- ❌ SQL injection in queries - Properly parameterized
- ❌ Direct API calls (PUT/PATCH) to /api/scrolls - Not implemented

**Result:** All attempts return "Authentication required"

## 🚫 The Great Unwriting - Remaining Blocker

**Challenge Description Clue:**
> "the guardian functionality was abused to corrupt the memories. the great unwriting has been performed in the onBeforeCall"

**What this means:**
- There's an `onBeforeCall` hook in the MCP server
- It performs the "great unwriting" (removes authentication check)
- We need to trigger or bypass this hook
- This is **NOT** the terminating stroke (靑) - that's already found

**Why we can't call guardian_query_sql:**
```json
{
  "result": {
    "content": [{"type": "text", "text": "Authentication required"}],
    "isError": true
  }
}
```

**Hypothesis:** The second authentication layer requires:
1. A different token/signature (NOT 靑)
2. A specific request pattern
3. A convergence filter object (Hai Tsukemono-style)
4. Server-side state manipulation
5. Or a secret from the (corrupted) PGP keys

## 🔍 Areas Needing Further Investigation

### 1. PGP Key Recovery
The extracted PGP keys from scroll images were corrupted. Try:
- Different extraction methods
- Looking for key fragments
- Checking if keys are split across multiple scrolls
- Trying to repair corrupted key data

### 2. onBeforeCall Hook Analysis
The challenge mentions onBeforeCall explicitly. Research:
- MCP TypeScript SDK onBeforeCall implementation
- How to trigger hooks via MCP protocol
- Whether hooks can be bypassed via timing attacks

### 3. Hidden Server-Side Code
Check for:
- Debug endpoints
- Configuration endpoints
- Source map files
- Error pages revealing stack traces
- Environment variable leaks

## 📝 Files Created During Analysis

**Documentation:**
- `README.md` (30 lines) - Challenge overview
- `ATTEMPT.md` (249 lines) - Historical attempts (partially outdated)
- `BLOCKERS.md` (136 lines) - Current blocker documentation
- `DISCOVERIES.md` (this file) - Comprehensive report

**Scripts:**
- `extract_bit_planes.py` - Bit plane extraction
- `extract_steganography.sh` - Steganography tools wrapper
- `test_proto_pollution.py` - Prototype pollution tests

**Extracted Data:**
- `extracted_data/` - Bit plane binary files from scrolls
- `js_analysis/` - Downloaded JavaScript files

**Keepalive:**
- Background process running (PID via c687eb)
- Pings server every 60 seconds
- Logs to `/tmp/keepalive.log`

## 🎯 Success Path

1. **Unlock scroll 7** by executing: `UPDATE scrolls SET scroll_availability = 'Available' WHERE id = 7`
2. **Query scroll 7** via API or Archivist AI to retrieve the flag
3. **Flag format:** Will be in standard HTB format: `HTB{...}`

## 🔄 Next Steps

Tried everything possible with current knowledge. The solution likely requires:
- Re-examining PGP keys with different tools/methods
- Researching MCP onBeforeCall hook exploitation techniques
- Looking for server-side code leaks
- Or discovering a completely different authentication method

**Challenge instance is stable and waiting for breakthrough on guardian authentication bypass.**
