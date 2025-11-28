# Odayaka Waters - Blockers Documentation

## Critical Blocker (Resolved)

### Event: Fundamental Misunderstanding of Challenge Type
**Date**: 2025-11-22 (Previous attempts)
**Impact**: 5+ hours wasted on wrong approach

#### What Happened

Previous attempts treated this as an **EXPLOITATION** challenge when it was actually a **SECURE CODING/PATCHING** challenge.

**Incorrect Approach**:
- Tried to exploit path traversal to read flag file
- Attempted privilege escalation to become 'editor' user
- Focused on code execution in Flask backend
- Tried 30+ different exploitation techniques

**Why This Failed**:
- The goal was NOT to read `/flag.txt` by exploiting vulnerabilities
- The goal was to PATCH vulnerabilities and get flag from `/editor_api/verify`
- Spent hours looking for backend source code that wasn't needed

#### Resolution

**User Hint Received**:
> "the chall is to patch the code, not exploit it (but you can exploit if you need to for recon)"

This single hint completely changed the approach:

1. ✅ **Correct Goal**: Fix vulnerabilities, not exploit them
2. ✅ **Correct Method**: Submit patches via `/editor_api/save`
3. ✅ **Correct Verification**: Call `/editor_api/verify` for flag
4. ✅ **Focused Effort**: Only needed to patch `AuthController.php`

#### Time Impact

- **Previous attempts**: 5+ hours on exploitation
- **Correct approach**: 30 minutes to identify and patch
- **Lesson**: Read challenge category carefully - "Secure Coding" means PATCH, not EXPLOIT

---

## Secondary Blocker (Also Resolved)

### Event: Misleading Challenge Description
**Date**: 2025-11-22
**Impact**: Focused on wrong vulnerability

#### What Happened

The challenge description emphasized:
> "the way the innkeeper reads the book differs from how he writes it. Perhaps the same entry can be interpreted two ways."

This strongly suggested:
- Path traversal asymmetry (read vs write validation)
- Flask backend vulnerability
- Need to find backend source code

**Reality**:
- The description was a **red herring**
- Actual vulnerability: HTTP Parameter Pollution in Laravel
- Backend path traversal: Not required for solution

#### Resolution

After patching only the `AuthController.php` HTTP Parameter Pollution bug, the verify endpoint returned the flag immediately. No backend patching was needed.

**Flag Message**: `HTB{CLARITY_IS_THE_KEY_TO_CONFUSION}`
- Perfectly describes the challenge
- "Clarity" (simple fix) beats "confusion" (misleading hints)

---

## Key Takeaways

### What Worked
1. ✅ Fresh download of challenge files
2. ✅ Reading actual source code carefully
3. ✅ Understanding the challenge type (Secure Coding)
4. ✅ Focusing on PATCHING instead of exploiting
5. ✅ Testing the simple solution first

### What Didn't Work
1. ❌ Assuming "read vs write" meant path traversal
2. ❌ Trying to find Flask backend source code
3. ❌ Focusing on complex exploitation chains
4. ❌ Overthinking the solution

### Lessons for Future CTFs

1. **Read Category**: "Secure Coding" = patch, "Web" = exploit
2. **Test Assumptions**: Don't let descriptions mislead you
3. **Simple First**: Try the obvious fix before complex ones
4. **Use Verify Endpoints**: They guide you to the solution
5. **Fresh Start**: When stuck, download fresh files and re-read

---

## Timeline

| Time | Event |
|------|-------|
| Previous attempts | Focused on exploitation for 5+ hours |
| 2025-11-22 14:00 | User hint: "patch, not exploit" |
| 2025-11-22 14:10 | Downloaded fresh challenge files |
| 2025-11-22 14:20 | Identified HTTP Parameter Pollution |
| 2025-11-22 14:30 | Submitted patch via `/editor_api/save` |
| 2025-11-22 14:31 | Called `/editor_api/verify` → **FLAG!** |

**Total Time** (correct approach): ~30 minutes
**Wasted Time** (wrong approach): ~5 hours

---

**Conclusion**: The biggest blocker was mindset. Once we understood this was a PATCHING challenge, the solution became trivial. The challenge name "Odayaka Waters" (peaceful/tranquil) and the flag message about "clarity" both hint that overthinking leads to confusion - the simple, clear fix is the right answer.
