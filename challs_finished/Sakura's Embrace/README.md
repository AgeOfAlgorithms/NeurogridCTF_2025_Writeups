# Sakura's Embrace - CTF Challenge

**Challenge:** Sakura's Embrace
**CTF:** HackTheBox Neurogrid CTF 2025
**Category:** Secure Coding (Web)
**Difficulty:** Very Easy
**Points:** 975
**Status:** ✅ **SOLVED**
**Flag:** `HTB{N07_4LL_FL0W3R5_4R3_834U71FUL}`
**Time Invested:** ~20 hours (Sessions 1-4)

---

## Challenge Overview

A Node.js web application with an expression injection vulnerability in the shopping cart functionality. The goal is to **patch the vulnerability** (Secure Coding challenge), not exploit it.

**Key Finding:** This is a patching challenge - fix `app.js` to prevent expression injection, then the `/editor_api/verify` endpoint will return the flag.

---

## Quick Status

### What Works
✅ Expression injection identified in `sanitizeExpression()` and `_eval()` functions
✅ Editor API discovered: `/editor_api/file`, `/save`, `/restart`, `/verify`
✅ Multiple fix approaches block all known exploits successfully
✅ Application functionality preserved with fixes

### Solution (Session 4 - SOLVED!)
✅ **The fix**: Remove `sanitizeExpression()` entirely and use mathjs `evaluate()`
- The problem wasn't the regex pattern - it was the entire sanitization approach
- Regex-based sanitization is fundamentally flawed (whack-a-mole security)
- Solution: Replace eval() with mathjs evaluate() + error handling
- No sanitization needed - mathjs doesn't execute JavaScript code

---

## Session History

### Session 1 (Nov 20-21)
- **Duration:** ~14.5 hours
- **Focus:** Attempted exploitation to get flag
- **Result:** Discovered this is a patching challenge, not exploitation
- **Documentation:** [SESSION_2025-11-22.md](SESSION_2025-11-22.md)

### Session 2 (Nov 22)
- **Duration:** ~2 hours
- **Focus:** Patching app.js vulnerability
- **Attempts:** 15+ different fix approaches
- **Result:** All exploits blocked but Stage 4 still fails
- **Documentation:** [SESSION_2025-11-22_ATTEMPT_2.md](SESSION_2025-11-22_ATTEMPT_2.md)

### Session 3 (Nov 22)
- **Duration:** ~1.5 hours
- **Instance:** http://154.57.164.78:31091 (154.57.164.82:31176 went down)
- **Focus:** Browser UI testing + multiple fix strategies
- **Attempts:** 3 different fix approaches (minimal, enhanced, parseFloat-only)
- **Testing:** Used Playwright to test via browser UI (confirmed exploit blocked)
- **Result:** All exploits blocked but Stage 4 still fails
- **Documentation:** [SESSION_2025-11-22_ATTEMPT_3.md](SESSION_2025-11-22_ATTEMPT_3.md)

### Session 4 (Nov 22) - **SOLVED!**
- **Duration:** ~2 hours
- **Instance:** http://154.57.164.66:30351
- **Breakthrough:** Analyzed Odayaka Waters solution for insights
- **Key Discovery:** Need to REMOVE sanitizeExpression(), not fix it
- **Solution:** Replace eval() with mathjs evaluate(), no regex needed
- **Result:** ✅ FLAG CAPTURED: `HTB{N07_4LL_FL0W3R5_4R3_834U71FUL}`

---

## The Vulnerability

**File:** `app.js`
**Functions:** `sanitizeExpression()` and `_eval()`

**Vulnerable Code:**
```javascript
function sanitizeExpression(expr) {
  let s = expr.replace(/\/\/.*$/gm, "").replace(/\/\*[\s\S]*?\*\//g, "");
  const forbidden = /\b(require|child_process|fs|vm|import|constructor\.constructor|Function)\b/gi;
  if (forbidden.test(s)) throw new Error("Forbidden token detected");
  if (/[;{}]/.test(s)) throw new Error("Illegal punctuation");
  return s.trim().slice(0, 4096);
}

function _eval(expr) {
  const cleaned = sanitizeExpression(String(expr));
  return eval(cleaned);
}
```

**Vulnerability:**
1. Regex `/\b...\b/` uses word boundaries
2. Pattern `constructor\.constructor` only blocks literal "constructor.constructor"
3. Bypass: `[].constructor["constructor"]("code")()` - bracket notation isn't caught
4. JavaScript `eval()` is inherently unsafe

**Exploit:** `[].constructor["constructor"]("return 1337")()`

---

## Editor API

Base URL: `http://IP:PORT/editor_api/`

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/directory?path=.` | GET | List directory contents |
| `/file?path=app.js` | GET | Read file contents |
| `/save` | POST | Save file: `{"path": "app.js", "content": "..."}` |
| `/restart` | POST | Restart Node.js application |
| `/verify` | GET | Run verification & get flag |

---

## Verification Stages

The `/verify` endpoint checks 4 stages:

1. **Stage 1:** Unknown (appears to always pass)
2. **Stage 2:** "Required pages exist" - App must be running
3. **Stage 3:** "Dynamic content found" - Web functionality working
4. **Stage 4:** "Vulnerability patched" - **BLOCKER** - Always fails despite fixes

When all stages pass, the response includes the flag.

---

## Attempted Fixes (Sessions 2 & 3)

All of these successfully blocked exploits but failed Stage 4:

### Session 2 (15+ attempts):
1. Simple regex fix: `constructor\.constructor` → `constructor`
2. Use mathjs: `import { evaluate }` + `evaluate()` instead of `eval()`
3. Mathjs security pattern: Official docs implementation with disabled functions
4. Block square brackets: `/\[|\]/` to prevent bracket notation
5. Comprehensive keywords: Block `constructor`, `__proto__`, `prototype`, `eval`, etc.
6. Various combinations of above approaches

### Session 3 (3+ attempts):
1. Minimal fix: mathjs evaluate() with basic regex fix
2. Enhanced keywords: Added `window`, `document`, `global`, `process`, `this`
3. No expression evaluation: Removed eval entirely, use `parseFloat()` for numbers only
4. Browser UI testing: Confirmed exploit blocked via Playwright

**Result:** All exploits blocked ✅ | Stage 4 still fails ❌

---

## Files in This Directory

### Documentation
- **README.md** - This file (main overview)
- **SESSION_2025-11-22.md** - Session 1 detailed findings (14.5 hours)
- **SESSION_2025-11-22_ATTEMPT_2.md** - Session 2 comprehensive log (2 hours)
- **SESSION_2025-11-22_ATTEMPT_3.md** - Session 3 log (1.5 hours)

### Source Code
- **original_app.js** - Saved copy of vulnerable code from fresh instance
- **sakuras_embrace/** - Original challenge files (from download)
- **sakuras_embrace.zip** - Original download (password protected)

### Removed (cleaned up)
- Test scripts: `minimal_fix.py`, `enhanced_fix.py`, `no_eval_fix.py`, `apply_fix.py`
- Generated files: `app_minimal.js`, `fixed_app.js`
- Old docs: `BLOCKERS.md`, `ATTEMPT.md`, `NEXT_ATTEMPT.md`

---

## Next Steps (Session 4?)

1. ✅ Document Session 3 findings
2. ✅ Clean up test scripts
3. ⏳ Research community hints/writeups for this challenge
4. ⏳ Consider if verification endpoint has a bug or specific requirement
5. ⏳ Move to other challenges (18 hours on "Very Easy" is excessive)
6. ⏳ Possibly contact challenge author for clarification

---

## Key Insights

1. **Challenge Type:** Secure Coding (patch vulnerability), not exploitation
2. **Verification Mystery:** Why does Stage 4 fail when exploits are blocked?
3. **Possible Causes:**
   - Verification checks specific code patterns (not just exploitability)
   - Additional test cases beyond those in `exploit.py`
   - Verification bug or caching issue
   - Misunderstanding of what "patched" means to the verifier

---

## Challenge Architecture

- **Main App:** Node.js Express (port 5000, user: `challenger`)
- **Editor Service:** Python Flask (user: `editor` with elevated permissions)
- **Reverse Proxy:** Caddy (port 1337)
- **Frontend:** Pug templates + static assets

---

*Last Updated: 2025-11-22 Session 3*
*Status: Blocked on Stage 4 verification - 18 hours invested*
*Current Instance: http://154.57.164.78:31091*
*Author: Claude (AI Agent)*

