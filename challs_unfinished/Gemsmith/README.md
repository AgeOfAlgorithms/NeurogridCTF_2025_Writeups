# Gemsmith - PWN Challenge

**CTF:** HackTheBox Neurogrid CTF 2025
**Category:** PWN
**Difficulty:** Hardest (1/142 solves - 0.7%)
**Status:** ❌ Unsolved
**Time Invested:** 30+ hours
**Date:** 2025-11-21 to 2025-11-23

---

## Challenge Overview

Binary that allows 14 operations to "forge a sword" using gem allocation/deletion. Goal is to "upgrade" the sword rather than let it break after 14 operations.

### Files
- `challenge/gemsmith` - Main binary (PIE, Full RELRO, Canary, NX)
- `challenge/glibc/libc.so.6` - GLIBC 2.27-3ubuntu1.6 (tcache enabled)
- `challenge/glibc/ld-linux-x86-64.so.2` - Dynamic linker

---

## Vulnerabilities

### 1. NULL Write Primitive
```c
sVar5 = read(0, buf[0], size-1);     // Read N bytes
(&buf)[(int)sVar5] = 0;               // NULL qword at buf[bytes_read]
```
**Impact:** Sending N bytes → NULLs 8-byte qword at `buf_address + N*8`

### 2. Use-After-Free
```c
void delete(void) {
    free((void *)(&buf)[iVar2]);
    // ⚠️ Pointer not NULLed - dangling pointer remains
}
```

### 3. Index Restriction
**CRITICAL:** Only index 0 is valid. Negative indices are REJECTED (tested and confirmed).

---

## What We Know

### Binary Behavior
- Exactly 14 operations allowed
- After 14 ops: calls `fail("sword broken")` then `exit(0x520)`
- No flag embedded in binary
- No hidden win/success functions

### Memory Layout (PIE base varies)
```
0x303010: stdout pointer
0x303020: stdin pointer
0x303030: buf[0] (our allocation)
0x304000: heap starts (≈4KB after buf)
```
**Key Insight:** stdin/stdout are BEFORE buf, so forward NULL writes can only reach heap, not global pointers.

### Function Behaviors (from GDB Analysis)
- **delete()** - Calls `success("🗑️ Gemu wa sakujo saremashita")` then returns (no exit!)
- **fail()** - Calls `exit(0x520)` (terminates program)
- **success()** - Prints message and returns normally (no exit)
- **show()** - Calls `puts(buf[0])` to print heap contents
- **Main loop** - After 14 ops, calls `fail("⚔️ Ken wa kowarete shimaimashita :(")` = "The sword broke"

### Tested & Failed Approaches
1. ❌ Negative index exploitation (doesn't work - only index 0 valid)
2. ❌ GOT overwrites (can't access without negative indices)
3. ❌ Completing 14 normal operations (always shows "broken")
4. ❌ Heap corruption via NULL writes (crashes but no flag)
5. ❌ Pattern-based "forging" (no pattern found)
6. ❌ Menu option 4 (just error message)
7. ❌ Backward NULL writes to stdin/stdout (memory layout prevents this)

---

## Files

### Documentation
- **README.md** (this file) - Main overview and current status
- **ATTEMPT.md** - Complete 30+ hour exploitation timeline
- **GDB_ANALYSIS.md** - Deep GDB analysis session findings (2025-11-23)

### Scripts
- `challenge/test_baseline.py` - Basic connection test
- `challenge/*.sh` - GDB analysis scripts (memory layout, function comparison, etc.)
- `challenge/decode_messages.py` - Decode fullwidth Japanese strings from binary
- `challenge/test_tcache_corruption.py` - Systematic tcache exploitation tests

---

## Current Blockers

1. **Unknown Flag Delivery:** Flag not in binary, must come from server
2. **Unknown Trigger:** What causes flag revelation?
3. **0.7% Solve Rate:** Suggests very specific trick/knowledge required
4. **"Think Outside Box":** Implies non-obvious approach

---

## Next Steps (If Continuing)

1. Seek writeup from team "ai-agent-of-x0f3l1x" who solved it
2. Test all heap corruption offsets systematically (0-1055)
3. Research GLIBC 2.27 edge cases
4. Check for server source code availability

---

**Last Updated:** 2025-11-23 19:45
**See ATTEMPT.md for complete 30+ hour analysis timeline**

### Recent GDB Analysis Session (2025-11-23)

Conducted deep binary analysis using GDB batch mode with pre-created input files to work around interactive limitations:

**Key Discoveries:**
1. Only 2 exit points exist: `fail()` at multiple call sites and final `fail()` in main
2. `success()` and `fail()` are nearly identical except fail() calls `exit(0x520)`
3. `delete()` ALWAYS calls `success()` (not fail), which returns normally
4. No "upgrade" or "complete" strings found in binary - only "broken" message
5. Memory layout confirms forward-only NULL writes (heap corruption only)
6. All .rodata strings decoded - no hidden messages or flags

**Analysis Tools Created:**
- [check_memory_layout.sh](challenge/check_memory_layout.sh) - Runtime memory mapping
- [compare_success_fail.sh](challenge/compare_success_fail.sh) - Function comparison
- [examine_rodata.sh](challenge/examine_rodata.sh) - String extraction
- [decode_messages.py](challenge/decode_messages.py) - UTF-8 fullwidth text decoder

**Remaining Mystery:** With only 14 operations and no apparent way to prevent the final `fail("sword broken")`, the solution likely involves:
- Server-side detection of specific heap state or output pattern
- Undiscovered tcache exploitation leading to arbitrary write
- Novel technique not yet considered ("think outside the box")
