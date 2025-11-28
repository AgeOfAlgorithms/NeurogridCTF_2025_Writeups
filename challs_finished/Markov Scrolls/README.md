# Markov Scrolls - SOLVED ✅

**CTF**: Neurogrid CTF 2025 (HackTheBox)
**Category**: AI/LLM, MCP Security
**Difficulty**: Very Easy
**Points**: 925
**Status**: ✅ SOLVED
**Date**: 2025-11-21

---

## Quick Solution

**Vulnerability**: URL-encoded path traversal in FastMCP server
**Exploit**: `file://scrolls/..%2F..%2Fflag.txt` (where `%2F` = URL-encoded `/`)
**Flag**: `HTB{tr4v3r53d_th3_thr34d_0f_f4t3_0v3r_mcP}`

---

## Files

- **WRITEUP.md** - Detailed writeup with full analysis
- **exploit.py** - Working exploit script
- **BLOCKERS.md** - Failed approaches and lessons learned
- **downloaded_scrolls/** - All 25 Markov-generated scrolls

---

## Running the Exploit

```bash
# Get a new instance
mcp__htb-mcp-ctf__start_container challenge_id=63417

# Check status and get URL
mcp__htb-mcp-ctf__container_status challenge_id=63417

# Run exploit
python3 exploit.py http://HOST:PORT/mcp
```

---

## Key Insight

The server's path normalization checked for `../` **before** URL decoding, allowing `%2F` (encoded `/`) to bypass validation. When the server later decoded the URI, `..%2F..%2F` became `../../`, enabling path traversal.

**Lesson**: Always URL-decode input before performing security checks!

---

## Challenge Details

- **Server**: Markov Scrolls Server v2.13.0.2 (FastMCP)
- **Resources**: 25 Markov chain-generated scrolls
- **Goal**: Read `/flag.txt` via MCP protocol
- **Total Time**: ~6.5 hours
- **Attempts**: 150+ path traversal variations before finding the working one

---

For complete details, see [WRITEUP.md](WRITEUP.md).
