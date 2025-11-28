# Sakura's Embrace - Solution Summary

## Challenge Information
- **Name**: Sakura's Embrace
- **Category**: Secure Coding (Web)
- **Difficulty**: Very Easy
- **Points**: 925
- **Flag**: `HTB{N07_4LL_FL0W3R5_4R3_834U71FUL}`
- **Solves**: 16
- **Time Invested**: 20+ hours (4 sessions)

---

## The Solution

### The Vulnerability
Expression injection in `app.js` - using `eval()` with flawed regex sanitization.

### The Fix (3 Changes Required)

**Change 1: Add mathjs import** (after line 7)
```javascript
import { evaluate } from 'mathjs';
```

**Change 2: Remove `sanitizeExpression()` function** (delete lines 26-32)

**Change 3: Replace `_eval()` function** (replace lines 34-36)
```javascript
function _eval(expr) {
  try {
    const result = evaluate(String(expr));
    return typeof result === 'number' && Number.isFinite(result) ? result : NaN;
  } catch {
    return NaN;
  }
}
```

---

## Why It Works

- ❌ **Don't**: Try to sanitize eval() with regex
- ✅ **Do**: Replace eval() with mathjs evaluate()
- 🎯 **Key Insight**: The `sanitizeExpression()` function itself was the problem, not just the regex pattern

---

## Deployment

```python
import requests

HOST = "http://IP:PORT"

# Get original
r = requests.get(f"{HOST}/editor_api/file?path=app.js")
original = r.json()["content"]

# Add import
fixed = original.replace(
    "import dotenv from 'dotenv';",
    "import dotenv from 'dotenv';\nimport { evaluate } from 'mathjs';"
)

# Remove sanitizeExpression and replace _eval
old_section = """function sanitizeExpression(expr) {
  let s = expr.replace(/\\/\\/.*$/gm, "").replace(/\\/\\*[\\s\\S]*?\\*\\//g, "");
  const forbidden = /\\b(require|child_process|fs|vm|import|constructor\\.constructor|Function)\\b/gi;
  if (forbidden.test(s)) throw new Error("Forbidden token detected");
  if (/[;{}]/.test(s)) throw new Error("Illegal punctuation");
  return s.trim().slice(0, 4096);
}

function _eval(expr) {
  const cleaned = sanitizeExpression(String(expr));
  return eval(cleaned);
}"""

new_section = """function _eval(expr) {
  try {
    const result = evaluate(String(expr));
    return typeof result === 'number' && Number.isFinite(result) ? result : NaN;
  } catch {
    return NaN;
  }
}"""

fixed = fixed.replace(old_section, new_section)

# Deploy
requests.post(f"{HOST}/editor_api/save", json={"path": "app.js", "content": fixed})
requests.post(f"{HOST}/editor_api/restart")

# Get flag
r = requests.get(f"{HOST}/editor_api/verify")
print(r.json()["flag"])  # HTB{N07_4LL_FL0W3R5_4R3_834U71FUL}
```

---

## Lessons Learned

1. **Regex sanitization is fundamentally flawed** - use safe alternatives instead
2. **eval() cannot be made safe** - replace it entirely with mathjs
3. **Secure Coding challenges require patching, not exploitation**
4. **"Think outside the box"** - the solution was to remove the sanitization, not fix it
5. **Read package.json** - mathjs was already a dependency (hint!)

---

## Failed Attempts (20 Hours)

- ❌ Fix regex pattern only
- ❌ Use mathjs BUT keep sanitizeExpression
- ❌ Use parseFloat (breaks functionality)
- ❌ Add input validation with mathjs
- ❌ Disable mathjs dangerous functions

**✅ What Worked**: Remove sanitizeExpression entirely + use mathjs evaluate()

---

**Documentation**:
- Full writeup: [WRITEUP.md](WRITEUP.md)
- Original vulnerable code: [ORIGINAL_vulnerable_app.js](ORIGINAL_vulnerable_app.js)
- Session logs: [SESSION_*.md](SESSION_2025-11-22.md)
