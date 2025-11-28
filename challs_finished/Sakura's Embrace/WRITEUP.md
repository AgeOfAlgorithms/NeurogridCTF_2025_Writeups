# Sakura's Embrace - Writeup

**Challenge**: Sakura's Embrace
**Category**: Secure Coding (Web)
**Difficulty**: Very Easy
**Points**: 925
**Status**: ✅ **SOLVED**
**Flag**: `HTB{N07_4LL_FL0W3R5_4R3_834U71FUL}`

---

## Challenge Description

> "In the merchant quarter, Kenji investigates Senmonten, a specialty shop selling yunomi teacups and matcha bowls beneath falling cherry blossoms. The shopkeeper uses an abacus to tally purchases and has built safeguards to prevent tampering. Yet Kenji suspects one clever arrangement might let a customer rewrite their total entirely."

**Challenge Type**: This is a **SECURE CODING** challenge - you must PATCH the vulnerability, not exploit it.

---

## TL;DR

1. **Identify** the expression injection vulnerability in `app.js`
2. **Remove** the flawed `sanitizeExpression()` function entirely
3. **Replace** `eval()` with mathjs `evaluate()`
4. **Submit** via `/editor_api/save` and **verify** via `/editor_api/verify`

---

## The Vulnerability

**File**: `app.js` (lines 26-36)

**Vulnerable Code**:
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
  return eval(cleaned);  // ← DANGEROUS!
}
```

**Two Critical Issues**:

1. **Flawed Regex Pattern**: `/\b(constructor\.constructor)\b/` only blocks the literal string "constructor.constructor", but NOT bracket notation: `constructor["constructor"]`

2. **Regex Sanitization is Fundamentally Flawed**: Even if you fix the regex pattern, trying to sanitize `eval()` input is inherently insecure. There are countless bypass techniques.

**Exploitation**:
```javascript
// Payload that bypasses the regex
[].constructor["constructor"]("return 1337")()

// When used in quantity field:
POST /cart/add
itemId=1&quantity=[].constructor["constructor"]("return 1337")()

// Result: arbitrary code execution
```

---

## The Fix

**DO NOT** try to fix the regex! **DO NOT** try to sanitize eval()!

**Instead**: Remove the entire sanitization approach and use a safe evaluation library.

### Step 1: Add mathjs Import

**After line 7** (after `import dotenv from 'dotenv';`):
```javascript
import { evaluate } from 'mathjs';
```

### Step 2: Remove sanitizeExpression() Entirely

**Delete lines 26-32** (the entire `sanitizeExpression` function)

### Step 3: Replace _eval() with Safe mathjs Evaluation

**Replace lines 34-36** with:
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

## Complete Patched Code

**Before** (vulnerable):
```javascript
import dotenv from 'dotenv';
dotenv.config();

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

**After** (patched):
```javascript
import dotenv from 'dotenv';
import { evaluate } from 'mathjs';
dotenv.config();

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

## Why This Works

### ❌ What DOESN'T Work

1. **Just fixing the regex**: `constructor\.constructor` → `constructor`
   - Still vulnerable to other bypasses
   - Regex sanitization is whack-a-mole security

2. **Using mathjs BUT keeping sanitizeExpression**:
   - The flawed validation logic is still present
   - The verifier checks for the ABSENCE of vulnerable patterns

3. **Replacing eval with parseFloat/parseInt**:
   - Breaks the application (can't evaluate expressions like "2+3")

### ✅ What DOES Work

- **mathjs `evaluate()`**: Designed for safe mathematical expression evaluation
- **No JavaScript code execution**: mathjs parses expressions mathematically, not as code
- **Type safety**: Verify result is a finite number
- **Error handling**: Invalid expressions return NaN gracefully

---

## Solution Steps

### 1. Start Fresh Instance
```bash
# Via HTB MCP or manually
curl http://IP:PORT/editor_api/file?path=app.js
```

### 2. Apply the Patch

```python
import requests

HOST = "http://IP:PORT"

# Get original code
r = requests.get(f"{HOST}/editor_api/file?path=app.js")
original = r.json()["content"]

# Add mathjs import
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

# Save
requests.post(f"{HOST}/editor_api/save", json={"path": "app.js", "content": fixed})

# Restart
requests.post(f"{HOST}/editor_api/restart")

# Verify and get flag
r = requests.get(f"{HOST}/editor_api/verify")
print(r.json())  # {"flag": "HTB{N07_4LL_FL0W3R5_4R3_834U71FUL}"}
```

### 3. Verify

```bash
curl http://IP:PORT/editor_api/verify
```

**Expected Response**:
```json
{"flag": "HTB{N07_4LL_FL0W3R5_4R3_834U71FUL}"}
```

---

## Key Lessons Learned

1. **Regex Sanitization is Flawed**: Don't try to blacklist dangerous patterns - use safe alternatives
2. **eval() is Inherently Unsafe**: Even with sanitization, eval() can be bypassed
3. **Use Purpose-Built Libraries**: mathjs is designed for safe expression evaluation
4. **Secure Coding ≠ Exploitation**: The goal is to FIX vulnerabilities, not bypass them
5. **Read the Dependencies**: mathjs was already in `package.json` - a hint to use it!
6. **Think Outside the Box**: The fix isn't to patch the regex - it's to remove it entirely

---

## Common Mistakes (20+ Hours of Failed Attempts)

### ❌ Attempt 1: Just Fix the Regex
- Changed `constructor\.constructor` → `constructor`
- Exploit blocked ✅
- Stage 4 verification failed ❌

### ❌ Attempt 2: Use mathjs BUT Keep sanitizeExpression
- Added mathjs, replaced eval with evaluate
- BUT kept sanitizeExpression function
- Exploit blocked ✅
- Stage 4 verification failed ❌

### ❌ Attempt 3: Use parseFloat
- Replaced _eval with parseFloat()
- Exploit blocked ✅
- BUT broke application functionality (can't evaluate "2+3")
- Stage 4 verification failed ❌

### ✅ Correct Solution: Remove sanitizeExpression + Use mathjs
- Removed entire sanitizeExpression function
- Replaced _eval with mathjs evaluate() + error handling
- Exploit blocked ✅
- Functionality preserved ✅
- **Stage 4 verification PASSED** ✅

---

## Flag

```
HTB{N07_4LL_FL0W3R5_4R3_834U71FUL}
```

**Translation**: "Not all flowers are beautiful"
**Meaning**: Not all solutions that look safe (regex sanitization) are actually secure.

---

## References

- [mathjs Security Documentation](https://mathjs.org/docs/expressions/security.html)
- [mathjs Secure Eval Example](https://mathjs.org/examples/advanced/more_secure_eval.js.html)
- HTB Neurogrid CTF 2025
- Inspiration from Odayaka Waters (similar Secure Coding challenge)

---

**Solved**: 2025-11-22 (after 20+ hours across multiple sessions)
**Points**: 925
**Solves**: 16 at time of completion
**Key Insight**: "Think outside the box" - don't fix the regex, remove it entirely!
