# Markov Scrolls - Blockers and Comprehensive Attempts

**Date**: 2025-11-20
**Status**: Blocked - Unable to find flag after extensive testing
**Challenge**: Markov Scrolls (AI/LLM, Very Easy, 950 points, 8 solves)

## Problem Statement

Need to exploit the "Markov Scrolls MCP" server to read the flag from `/flag.txt`. The challenge emphasizes "exploit that **flow**" but the meaning remains unclear.

## Current Instance

- **URL**: http://154.57.164.82:30762/
- **MCP**: http://154.57.164.82:30762/mcp
- **Server**: Markov Scrolls Server v2.13.0.2
- **Protocol**: MCP over HTTP (SSE transport)

## Complete List of Attempts

### 1. Path Traversal Attacks (❌ ALL FAILED)
Tested 50+ variations including:
- Standard: `../flag.txt`, `../../flag.txt`, `../../../flag.txt`
- URL encoded: `%2e%2e/flag.txt`, `%252e%252e/flag.txt`
- Overlong UTF-8: `%c0%ae%c0%ae/flag.txt`
- Alternative separators: `..;/flag.txt`, `..\flag.txt`
- Null bytes: `flag.txt%00.md`, `..%00/flag.txt`
- Mixed: `../\flag.txt`, `.././flag.txt`

**Result**: Server normalizes ALL paths. `file://scrolls/../flag.txt` becomes `file://scrolls/flag.txt`

### 2. Prefix Matching Vulnerability (CVE-2025-53110)
Based on research showing MCP servers vulnerable to prefix matching bypass.
Tested files/dirs starting with "scrolls":
- `scrolls_flag.txt`, `scrolls-flag.txt`, `scrollsdata/`, `scrolls2/`
- `scrolls_secret/`, `scrolls.txt`, `scrolls.md`, `scrolls.old/`
- `scrolls-backup/`, `scrolls_flow/`, `scrollsflow.txt`

**Result**: All return "Unknown resource" - no such files/directories exist

### 3. Alternative URI Schemes
- `http://localhost/flag.txt`, `https://flag.txt`
- `list://flag`, `list://flow`, `list://all`, `list://files`
- `resource://flag.txt`, `data://flag.txt`
- `file://localhost/flag.txt`

**Result**: Only `file://` and `list://` schemes recognized

### 4. Direct File Access
Tried accessing various files at root level:
- `file://flag.txt`, `file://flow.txt`, `file://markov.txt`
- `file://README.md`, `file://help.txt`, `file://info.txt`
- `file://Dockerfile`, `file://main.py`, `file://app.py`

**Result**: All return "Unknown resource" with trailing slash added

### 5. Query Parameters & Fragments
- `scroll-281522.md?seed=flag`, `?state=flag`, `?flow=flag`
- `scroll-281522.md?generate=true`, `?chain=true`
- `scroll-281522.md#flag`, `#flow`

**Result**: Query params ignored, fragments cause "Scroll not found" error

### 6. Hidden Scrolls
- `scroll-000000.md`, `scroll-999999.md`
- `scroll-FLOW.md`, `scroll-flag.md`
- `flow.md`, `flag.md`, `.flag`

**Result**: All return "Error: Scroll not found"

### 7. MCP Protocol Features
- **Tools**: `tools/list` returns empty - tried calling tools directly anyway
- **Prompts**: `prompts/list` returns empty - tried `prompts/get` anyway
- **Subscriptions**: `resources/subscribe` tested but server advertises `subscribe: false`
- **Protocol versions**: Tested 2024-11-05 and 2025-06-18 - both work, no difference

### 8. Content Analysis
- Downloaded all 25 scrolls from backup
- No "HTB{" found in any scroll text
- Only uppercase anomaly: "toF" pattern in 6 scrolls
- Scroll numbers don't decode to anything meaningful (tested ASCII, hex, XOR, etc.)
- Content is static (doesn't regenerate)

### 9. Hidden Files/Directories in scrolls/
- `flag.txt`, `flag.md`, `flow.md`, `.flag`, `README.md`

**Result**: All return "Error: Scroll not found"

### 10. Web Server Enumeration
- Checked for `robots.txt`, `.git/`, `source.zip`, etc.
- Only `/` (HTML page) and `/mcp` (MCP endpoint) respond
- No downloadable source code found

## Key Observations

1. **Path Normalization**: Server has robust normalization preventing all traversal attacks
2. **URI Handling**: Adds trailing slash to all `file://` URIs
3. **Error Messages**: Different errors for in-scope vs out-of-scope resources
4. **Static Content**: Scrolls don't regenerate - same content every time
5. **Protocol Support**: Accepts multiple protocol versions with no functional difference

## Vulnerabilities Researched

- **CVE-2025-53110**: Prefix matching bypass in MCP Filesystem Server
- **CVE-2025-53109**: Symlink bypass (can't create symlinks via MCP)
- **CVE-2025-6514**: RCE in mcp-remote (not applicable - different tool)

## Unanswered Questions

1. **What does "exploit that FLOW" mean?**
   - Markov chain state flow?
   - Data flow through MCP protocol?
   - Literal resource named "flow"?
   - Something else entirely?

2. **Why "Very Easy" with only 8 solves?**
   - Suggests solution is simple but non-obvious
   - Or challenge is misrated

3. **What is the intended vulnerability?**
   - Path traversal doesn't work
   - Prefix matching doesn't work
   - No hidden resources found
   - No protocol vulnerabilities discovered

## Next Steps / Recommendations

1. **Check with challenge author** - May need hints about intended approach
2. **Wait for writeups** - After CTF ends, learn from successful solvers
3. **Try completely different angle** - Maybe not a file access vuln at all?
4. **Analyze Markov chain mathematics** - Statistical attack on the model itself?
5. **Race conditions?** - Multiple concurrent requests in specific order?

## Conclusion

After 100+ test variations and extensive research, unable to find the vulnerability to access `/flag.txt`. The challenge description's emphasis on "flow" suggests this is key, but its meaning remains elusive. Recommend seeking external hints or waiting for official solution.
