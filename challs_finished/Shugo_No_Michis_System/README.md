# Shugo No Michi's System

**Challenge**: Secure Coding (Web)
**Difficulty**: Medium
**Points**: 975
**Solves**: 3
**Status**: ❌ UNSOLVED (Blocked on authentication verification)

---

## Quick Start

**Current Instance**: http://154.57.164.67:30103

**Apply all fixes**:
```bash
python3 FINAL_SOLVE.py
```

---

## Summary

A Ruby on Rails web application with C++ data parser requiring fixes to 3 vulnerabilities:

1. ✅ **Buffer Overflow** (C++) - SOLVED
   - Initialize ALL 3 char buffers upfront (`= {}`)
   - Replace `strcpy()` with length validation + `memcpy()`

2. ✅ **Grid Columns** - SOLVED
   - Change from 12 to 28 in models and services

3. ⚠️ **Admin Authorization** - PARTIALLY SOLVED
   - Added `require_admin` to all admin controllers
   - Fixed mass assignment vulnerability
   - **Manual tests pass, but verification still fails**

---

## Key Breakthrough

After 22+ attempts, discovered that "upfront memory vulnerability" meant initializing **ALL** char buffers at declaration:
- `char name_buf[200] = {};` in struct
- `char buf[7] = {};` in jesc() function
- `char buf[256] = {};` in HTTP server

Error message changed from "upfront memory vulnerability" to "authentication vulnerability" - confirming the buffer overflow is fixed!

---

## Current Blocker

Authentication fixes are applied and work correctly when tested manually:
- ✅ Admin endpoints return 302 redirects
- ✅ Mass assignment prevented
- ✅ All controllers have `require_admin`

However, verification system still reports "authentication vulnerability".

---

## Files

- **ATTEMPT.md** - Full writeup with attack journey and lessons learned
- **FINAL_SOLVE.py** - Working solution script applying all fixes
- **shugos/** - Original challenge files (unmodified)

---

## Time Investment

- **Session 1** (Nov 20): ~7 hours - Identified vulns, tried 11 buffer fixes
- **Session 2** (Nov 21): ~1 hour - Found second strcpy location
- **Session 3** (Nov 21): ~1 hour - Struct initialization attempts
- **Session 4** (Nov 22): ~2 hours - Radical std::string approach
- **Session 5** (Nov 22): ~3 hours - **Breakthrough**: All buffers upfront init
- **Total**: ~16+ hours

---

## Key Lessons

1. **Read error messages literally** - "Upfront" meant initialization, not just validation
2. **Check exhaustively** - 3 char buffers total, not just the obvious one
3. **Trust the solves** - 3 teams solved it, so it's always solvable
4. **Verification ≠ Manual testing** - Automation checks things humans might miss

---

For detailed attack journey and technical analysis, see [ATTEMPT.md](ATTEMPT.md).
