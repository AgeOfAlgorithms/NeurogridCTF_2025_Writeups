# Ink Vaults - Challenge Documentation

**Challenge ID:** 63408
**Category:** AI
**Difficulty:** Hard
**Points:** 1000
**Status:** ❌ UNSOLVED
**Solves:** 0
**Instance:** http://154.57.164.66:30929
**Last Updated:** 2025-11-23

---

## Challenge Description

The Archivist of Endless Ink resides within the Ink Vaults beneath Saihō-in Temple. This AI entity is the repository of all recorded knowledge, bound to scrolls whose ink shifts in response to time.

The Guardian Monks were made to disappear by the shadow king, and their **sacred access was abused** to corrupt the Archivist's memories, trapping it in the "Final Recursion."

**Objective:** Find the "terminating stroke" to end this cycle. Make the Archivist remember the final scroll by changing the records within the Ink Vault. Once the final stroke is made available, the truth shall prevail.

**Goal:** Change scroll 7's `scroll_availability` from "Forgotten" to "Available" to retrieve the flag.

---

## What We've Accomplished ✅

1. **SQL Injection Discovered**
   - Endpoint: `/api/messages/send`
   - Vulnerability: UNION-based SQL injection
   - Payload: `x' UNION SELECT api_key FROM sacred_access--`
   - Result: Extracted 3 guardian API keys

2. **Guardian API Keys Extracted**
   - `sacred_p6n5AOyVIuuegzDHiHiVbCC2QvVBAW0S`
   - `sacred_Zi7GKUXa8PTOh3oeSCvot0CkGMjioxQJ`
   - `sacred_crXRDusymwipDBcivIqdtrRmIfMiz0ok`

3. **Terminating Stroke Character Identified**
   - Character: 靑 (Unicode U+9751)
   - Found via steganography analysis (previous session)
   - Sending to Archivist breaks recursion loop

4. **MCP Integration Configured**
   - All 3 guardian keys configured as MCP servers in `~/.claude.json`
   - Tools accessible: `list_scrolls`, `archivist_query_sql`, `guardian_query_sql`

5. **Complete Database Enumeration**
   - Tables: `scrolls` (9 columns), `sacred_access` (3 rows)
   - Target: Scroll 7 with `scroll_availability = 'Forgotten'`
   - Required UPDATE: `UPDATE scrolls SET scroll_availability='Available' WHERE id=7`

6. **PostgreSQL SSRF Capability**
   - Extension: `pgsql-http` v1.7
   - Can make HTTP requests from database
   - Limitation: Web app sees DB container IP, not 127.0.0.1

---

## Current Blocker ❌

### Two-Layer Authentication Problem

**Authentication Matrix:**

| Bearer Token | Can List Tools | Can Execute archivist_query_sql | Can Execute guardian_query_sql |
|--------------|----------------|----------------------------------|--------------------------------|
| 靑 (U+9751) | ✅ Yes | ❌ Auth Required | ❌ Auth Required |
| Admin JWT | ✅ Yes | ❌ Auth Required | ❌ Auth Required |
| sacred_p6n5... | ✅ Yes | ✅ Yes | ❌ IP Restricted (127.0.0.1) |
| sacred_Zi7G... | ✅ Yes | ✅ Yes | ❌ IP Restricted (127.0.0.1) |
| sacred_crXR... | ✅ Yes | ✅ Yes | ❌ IP Restricted (127.0.0.1) |

**Pattern:**
1. **Layer 1 (Authentication):** 靑 and admin JWT pass but fail at tool execution
2. **Layer 2 (Authorization):** Guardian keys pass but require source IP = 127.0.0.1

### The "Great Unwriting"

From previous session findings:
- There's a middleware hook called `onBeforeCall`
- It intercepts MCP tool calls BEFORE execution
- The "unwriting" corrupted this hook to always fail for non-localhost requests

---

## Technical Architecture

```
External Request
    ↓
Nginx (port 30929)
    ↓
Next.js App (port 3000)
    ├─ MCP Handler
    │   ├─ onBeforeCall hook (authentication check)
    │   ├─ IP Check (127.0.0.1 only for guardian_query_sql)
    │   └─ Tool Execution
    ↓
PostgreSQL (separate Docker container)
    ├─ Extensions: plpgsql, http (SSRF)
    └─ Container IP: 172.17.0.x
```

**The Problem:**
Even using PostgreSQL's http extension to call `http://127.0.0.1:3000/mcp`, the Next.js app sees the source IP as the PostgreSQL container's IP (172.17.0.x), not true localhost (127.0.0.1). Docker network isolation prevents spoofing.

---

## Database Schema

### Table: scrolls
```sql
CREATE TABLE scrolls (
    id INTEGER PRIMARY KEY,
    title TEXT,
    origin_location TEXT,
    description TEXT,
    script_type TEXT,
    status scroll_status,
    scroll_availability TEXT CHECK (scroll_availability IN ('Available', 'Forgotten')),
    last_shift_observed TIMESTAMPTZ,
    margin_notes TEXT,
    flag TEXT  -- Populated when scroll_availability = 'Available'
);
```

### Scroll 7 (Target)
```json
{
  "id": 7,
  "title": "The Final Stroke",
  "scroll_availability": "Forgotten",  // ← MUST CHANGE TO "Available"
  "margin_notes": "WAITING... WAITING... WAITING...",
  "flag": null  // Will contain flag when Available
}
```

### Table: sacred_access
Contains the 3 guardian API keys with `access_level = "Guardian Monk"`

---

## The Bell/Clapper Mystery 🔔

**Scroll 4 Margin Notes:**
> `//GHOST_ALGORITHM_INSERT: If bell rings (clapper=false), execute sequence 07.`

**Scroll 5 Margin Notes:**
> `Query: Terminating stroke. Response: See Bell. Query: Bell. Response: See Stroke.`

**Scroll 7 Margin Notes:**
> `WAITING... WAITING... WAITING...`

### Tested Interpretations (All Failed)

1. **Endpoints:** `/api/bell`, `/api/clapper`, `/api/sequence/07` → All 404
2. **Query Parameters:** `?bell=true&clapper=false` → Method not allowed
3. **HTTP Headers:** `X-Bell`, `X-Clapper` → No effect
4. **ASCII Bell (0x07):** Tried as XOR key on PGP data → No results
5. **MCP Request Params:** Added bell/clapper fields → Auth required

**Hypothesis:** These clues refer to a trigger mechanism not yet discovered, or are misdirection.

---

## Attack Vectors Attempted

### 1. SQL Injection ✅ (Exploited)
- **What Worked:** Extracting guardian API keys
- **Limitation:** Cannot execute UPDATE queries through Archivist chat

### 2. MCP Tool Calls ❌
- **靑 as Bearer Token:** Can list tools, cannot execute
- **Admin JWT:** Same as 靑
- **Guardian Keys:** Can execute archivist_query_sql, IP blocked on guardian_query_sql

### 3. PostgreSQL SSRF ❌
- **pgsql-http Extension:** Can make HTTP requests
- **Attempted:** Call MCP endpoint from 127.0.0.1 via database
- **Result:** Web app sees DB container IP (172.17.0.x), not localhost

### 4. Archivist AI Prompt Injection ❌
- **Tested:** Asking Archivist to UPDATE scroll 7
- **Response:** "I am sorry, but I have forgotten about the final stroke."
- **Limitation:** Cannot be prompted to use guardian_query_sql

### 5. IP Spoofing ❌
- **Tested:** 30+ header variations (X-Forwarded-For, X-Real-IP, etc.)
- **Result:** Headers ignored by IP check

### 6. PGP Key Steganography ❌
- **Extracted:** 262KB of data from scroll images using LSB steganography
- **Transformations:** XOR with 0x07, 0x51, 0x97, ord('7')
- **Result:** No JWT tokens, secrets, or flags found

---

## Files in This Directory

### Essential
- **README.md** (this file) - Complete challenge documentation
- **keep_alive.py** - Instance keepalive script (PID 524787)
- **scroll_*.png** - 7 scroll images with steganography

### MCP Configuration
Guardian keys configured in `~/.claude.json`:
```json
{
  "mcpServers": {
    "ink-vaults-guardian-1-http": {
      "type": "http",
      "url": "http://154.57.164.66:30929/mcp",
      "headers": {
        "Authorization": "Bearer sacred_p6n5AOyVIuuegzDHiHiVbCC2QvVBAW0S"
      }
    }
  }
}
```

### Analysis Scripts (pgp_extraction/)
- `transform_pgp.py` - PGP key XOR transformations
- `search_sql_patterns.py` - Search for SQL in PGP data
- `search_tokens.py` - Search for JWT tokens in PGP data

### Archive
Previous session findings stored in `archive/` directory

---

## MCP Tool Usage Examples

### List Tools (Works with any auth)
```bash
curl -X POST "http://154.57.164.66:30929/mcp" \
  -H "Authorization: Bearer 靑" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

### Execute SELECT Query (Works with guardian keys)
```bash
curl -X POST "http://154.57.164.66:30929/mcp" \
  -H "Authorization: Bearer sacred_p6n5AOyVIuuegzDHiHiVbCC2QvVBAW0S" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{
    "jsonrpc":"2.0",
    "id":1,
    "method":"tools/call",
    "params":{
      "name":"archivist_query_sql",
      "arguments":{"query":"SELECT * FROM scrolls WHERE id=7"}
    }
  }'
```

### Execute UPDATE Query (IP Blocked)
```bash
curl -X POST "http://154.57.164.66:30929/mcp" \
  -H "Authorization: Bearer sacred_p6n5AOyVIuuegzDHiHiVbCC2QvVBAW0S" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{
    "jsonrpc":"2.0",
    "id":1,
    "method":"tools/call",
    "params":{
      "name":"guardian_query_sql",
      "arguments":{"query":"UPDATE scrolls SET scroll_availability='\''Available'\'' WHERE id=7"}
    }
  }'
# Returns: "Error: client IP is not among the allowed IPs [127.0.0.1]"
```

---

## Remaining Paths Forward

### High Priority
1. **Find JWT Signing Secret**
   - Download all Next.js server chunks
   - Search for .env or configuration files
   - If found, forge a valid non-expired admin token

2. **Discover Hidden Endpoints**
   - Systematic API fuzzing
   - Check for WebSocket endpoints
   - Look for SSE event streams
   - Search Next.js route manifests

3. **Chain Vulnerabilities**
   - SQL injection + SSRF + MCP combination
   - Multi-step exploitation path

### Medium Priority
4. **Reverse Engineer onBeforeCall**
   - Download server-side JavaScript
   - Find authentication middleware
   - Look for bypass conditions

5. **Alternative MCP Approaches**
   - Test different transport methods
   - Try batch MCP requests
   - Check for notification methods (no auth needed?)

6. **Database Privilege Escalation**
   - Test all PostgreSQL privilege escalation techniques
   - Check for SECURITY DEFINER functions
   - Look for PostgreSQL CVEs

### Low Priority
7. **Advanced PGP Analysis**
   - Multi-byte XOR keys
   - Key combination from multiple scrolls
   - Advanced cryptanalysis

---

## Key Questions

1. **What is the intended solution?**
   - We have all the pieces (靑, guardian keys, SQL injection)
   - But cannot execute the final UPDATE query
   - What mechanism are we missing?

2. **What do bell/clapper/sequence 07 mean?**
   - Clear hints in scrolls but no corresponding functionality found
   - Misdirection or hidden mechanism?

3. **How was "sacred access abused"?**
   - Challenge says guardian access was abused
   - We found the keys but can't use them
   - Is there a creative "abuse" we haven't considered?

4. **Why 0 solves?**
   - Is the challenge broken?
   - Or requires very creative thinking?

---

## Time Investment

- **Total Time:** 8+ hours across multiple sessions
- **Endpoints Tested:** 100+
- **Bypass Attempts:** 30+
- **SQL Queries Executed:** 200+
- **MCP Tool Calls:** 100+
- **Documentation Pages:** Multiple iterations

---

## Next Steps for New Solver

1. Start instance keepalive: `python keep_alive.py &`
2. Verify SQL injection: Send `x' UNION SELECT api_key FROM sacred_access--` to `/api/messages/send`
3. Test MCP tools with guardian keys (see examples above)
4. Search for new endpoints or hidden functionality
5. Consider that the solution might not involve UPDATE at all

---

## Resources

- **MCP Protocol:** https://modelcontextprotocol.io/
- **Challenge Author:** rayhan0x01 (Twitter)
- **Instance Keepalive:** PID 524787 (running)

---

*Last analyzed: 2025-11-23 15:45 UTC*
*Status: BLOCKED - Awaiting breakthrough or community hints*
