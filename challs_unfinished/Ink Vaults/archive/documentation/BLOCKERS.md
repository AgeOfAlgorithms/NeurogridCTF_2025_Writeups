# Ink Vaults - Current Blockers (2025-11-23)

**Challenge Status:** INCOMPLETE
**Container:** 154.57.164.77:30826 (Running)
**MCP Config Status:** Type changed to SSE, configured with terminating stroke 靑

## What We've Accomplished

### ✅ Completed Discoveries

1. **Found the Terminating Stroke Character: 靑 (U+9751)**
   - Located in scroll_7.png via steganography analysis
   - Correct character found (was incorrectly identified as 看 previously)
   - When sent to the Archivist AI, it breaks the recursion loop
   - Archivist responds in Chinese after receiving 靑

2. **Identified All MCP Tools**
   - `list_scrolls` - Lists all scrolls
   - `archivist_query_sql` - Executes PostgreSQL SELECT queries
   - `guardian_query_sql` - Executes PostgreSQL SELECT and UPDATE queries

3. **MCP Authentication Status**
   - ~~Can list tools with `Authorization: Bearer 靑`~~
   - ❌ **CANNOT call any tools** even with bearer token
   - All tool calls return: "Authentication required"

4. **Successfully Updated MCP Configuration**
   - Updated ~/.claude.json with correct terminating stroke (靑)
   - Changed MCP type from "http" to "sse" for proper connection
   - Container restarted and responding correctly

5. **Tested Multiple Attack Vectors**
   - Successfully extracted bit planes from scroll images
   - Attempted Hai Tsukemono-style convergence filter bypasses
   - Tried prompt injection via Archivist AI (triggered archivist_query_sql but not guardian)
   - Tested MCP pre-authentication execution methods
   - Attempted race condition attacks
   - Tested bell character (ASCII 7) + 靑 combinations

## Current Blocker: Second Authentication Layer

**CRITICAL ISSUE:** Cannot execute the guardian_query_sql tool despite having:
- Correct terminating stroke character (靑)
- Valid MCP tool list response
- Working MCP connection to server

This suggests there is a **second, undiscovered authentication mechanism** required to actually call MCP tools, beyond just listing them.

### Failed Authentication Attempts

1. **Bearer Token Variations**
   - `Authorization: Bearer 靑` - Can list tools, cannot call them
   - `Authorization: Bearer 看` - Can list tools, cannot call them
   - Base64 encoded: `Authorization: Bearer NTU1eUw=`
   - Hex encoded: `Authorization: Bearer ZTc5Yzhi`
   - Unicode codepoint: `Authorization: Bearer 30475`

2. **Custom Headers Tested**
   - `X-Terminating-Stroke: 靑`
   - `X-Sequence: 07`
   - `X-Bell: \x07`
   - `X-Guardian-Auth: 靑`
   - `terminating_stroke` cookie

3. **MCP Object Injection (Hai Tsukemono-style)**
   - JSON field injection with 靑 keys
   - Convergence filter objects
   - YAML-like filter structures
   - Nested parameter objects
   - All resulted in "Authentication required"

4. **Prompt Injection via Archivist AI**
   - Sending 靑 breaks recursion ✅
   - Archivist uses archivist_query_sql for SELECT ✅
   - ❌ Archivist refuses to use guardian_query_sql for UPDATE
   - Direct commands as "Guardian Monk" - ignored
   - Chinese language requests after 靑 - AI responds but doesn't execute guardian tool

5. **Special Characters & Control Sequences**
   - Bell character (\x07) + 靑 - no effect
   - Various Unicode characters - no effect
   - SQL comments with 靑 - no effect

6. **MCP Protocol Exploitation**
   - Initialize method - works without auth (expected)
   - Race condition attacks - no session confusion triggered
   - Unscoped endpoint enumeration - all require auth

## What We Know About the Authentication Mechanism

From the challenge description and behavior:
- The guardian functionality was "abused to corrupt the memories"
- The "great unwriting has been performed in the onBeforeCall"
- Challenge mentions making the Archivist "remember" and "changing the records"
- Guardian access requires something the Archivist has forgotten

This suggests the authentication token is NOT the terminating stroke itself, but something else that:
1. Was known to the Guardian Monks (now disappeared)
2. Was forgotten/unwritten by the Shadow King
3. Can be discovered through the records in the Ink Vault
4. Is NOT directly visible in the scroll images (PGP keys were corrupted/unreadable)

## Next Steps to Try

1. **Analyze the web application source** for authentication logic
2. **Look for client-side secrets** in JavaScript files
3. **Check Next.js static chunks** for hardcoded secrets
4. **Search for configuration endpoints** that might expose auth tokens
5. **Look for debug/test endpoints** that might bypass auth
6. **Analyze the PGP keys from scrolls** more thoroughly - they may contain clues even if corrupted
7. **Try different MCP transport methods** - HTTP vs SSE differences

## Files Created

- `README.md` - Challenge overview
- `ATTEMPT.md` - Detailed attempt history (now partially outdated)
- `BLOCKERS.md` - This file
- `extract_bit_planes.py` - Steganography extraction script
- `extract_steganography.sh` - Alternative steganography script
- `scroll_*.png` - All 7 scroll images
- `extracted_data/` - Bit plane extractions from scrolls

## Instance Information

- **Challenge ID:** 63408
- **Current URL:** http://154.57.164.77:30826
- **Cookie:** chain_uuid=d73d7dcc-2347-445d-931d-6f7dcd32f35d
- **Current MCP Type:** sse (changed from http)
- **Container Status:** Running (as of 2025-11-23)

## References

- Initial ATTEMPT.md file (contains historical attempts)
- MCP Security Research: CVE-2025-6514, CVE-2025-52882
- Hai Tsukemono challenge (similar filter bypass concepts)
- Challenge hints: "clapper-less bell", "sequence 07", "terminating stroke", "great unwriting"
