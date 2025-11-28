# Blockers Encountered - Sakura's Embrace

## Session 4 - Final Breakthrough (Nov 22, 2025)

### Event: Discovery of the Real Solution
**When**: After analyzing Odayaka Waters challenge (another Secure Coding challenge)
**What Happened**: Realized the fix wasn't to patch the regex, but to remove the entire `sanitizeExpression()` function
**Impact**: Immediate success after 20+ hours of failed attempts
**Blocker**: Fundamental misunderstanding of what needed to be patched

**What Changed**:
- Stopped trying to fix the regex pattern
- Stopped trying to keep sanitizeExpression with better checks
- Removed sanitization entirely and used mathjs evaluate()

**Key Insight from Odayaka Waters**:
- That challenge had TWO specific changes needed (not a rewrite)
- Both changes were required for verification to pass
- The pattern: minimal surgical fixes, not comprehensive rewrites

**Applied to Sakura's Embrace**:
- Change 1: Add mathjs import
- Change 2: Remove sanitizeExpression function
- Change 3: Replace _eval with mathjs evaluate()

---

## Sessions 1-3 - Extended Blocker (18+ Hours)

### Blocker: Stage 4 Verification Always Failed
**Duration**: 18+ hours across 3 sessions
**Symptom**: "Vulnerability still exists" despite exploit being blocked

**Failed Approaches** (all blocked exploit successfully but failed verification):
1. Minimal regex fix: `constructor\.constructor` → `constructor`
2. Regex fix + mathjs evaluate
3. Mathjs with disabled dangerous functions
4. Comprehensive keyword blocking
5. parseFloat only (broke functionality)
6. mathjs with empty scope
7. mathjs with secure configuration
8. Complete rewrite with mathjs (but kept sanitizeExpression)
9. Multiple combinations of the above

**Root Cause**: Kept the `sanitizeExpression()` function with regex checks
- Even with fixed regex, the sanitization approach itself was flawed
- Verifier was checking for absence of vulnerable patterns, not just functionality

**What We Learned**:
- Regex-based sanitization is fundamentally insecure (whack-a-mole)
- The solution isn't to fix the sanitization - it's to remove it
- Use purpose-built safe libraries (mathjs) instead of trying to sanitize eval()

---

## Key Learnings

1. **Don't patch broken security** - replace it with secure alternatives
2. **Regex sanitization can't be fixed** - it's inherently flawed
3. **Learn from similar challenges** - Odayaka Waters provided the crucial insight
4. **Read the hints** - mathjs in package.json was a clue
5. **"Think outside the box"** - sometimes the fix is removal, not modification

---

**Final Solution Documented In**:
- [WRITEUP.md](WRITEUP.md) - Complete writeup
- [SOLUTION.md](SOLUTION.md) - Quick solution summary
- [README.md](README.md) - Overview and session history
