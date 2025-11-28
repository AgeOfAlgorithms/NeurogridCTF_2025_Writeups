# GDB Analysis Session - Gemsmith

**Date:** 2025-11-23
**Duration:** ~1 hour
**Approach:** Static analysis using GDB batch mode

---

## Methodology

Since the program requires interactive input and GDB MCP cannot handle this, created bash scripts using GDB batch mode with pre-created input files:

```bash
# Example approach
echo -e "1\n0\n100\nAAAA\n" > /tmp/input
gdb -q gemsmith -batch \
  -ex "run < /tmp/input" \
  -ex "info proc mappings" \
  -ex "x/1gx &buf"
```

---

## Key Findings

### 1. Function Flow Analysis

**success() vs fail():**
- Both functions are nearly identical in structure
- **Critical difference:**
  - `fail()` calls `exit(0x520)` at offset 0xc74
  - `success()` just returns (ret at 0xd1b)
- Both print formatted messages with emojis/fullwidth text

**Call sites:**
```
success() called ONCE:   0xf51 (in delete function)
fail() called 5 times:   0xdb9, 0xe77, 0xeee, 0x10be, 0x1118
```

### 2. delete() Function Behavior

```c
void delete(void) {
    iVar2 = check_idx();
    success(&DAT_001014e0);  // ← ALWAYS called, doesn't exit!
    free((void *)(&buf)[iVar2]);
    return;
}
```

The success message: "🗑️　Ｇｅｍｕ　ｗａ　ｓａｋｕｊｏ　ｓａｒｅｍａｓｈｉｔａ" (The gem was deleted)

**Significance:** Unlike other operations, delete() calls success() which returns normally without exiting.

### 3. Memory Layout (from check_memory_layout.sh)

```
Address          Content           Distance from buf
---------------------------------------------------------
0x555555603010   stdout pointer    -32 bytes (BEFORE buf)
0x555555603020   stdin pointer     -16 bytes (BEFORE buf)
0x555555603030   buf[0]            Base address
0x555555604000   Heap start        +4000 bytes (AFTER buf)
```

**Critical Insight:** The NULL write primitive can only write forward into heap space, not backward to stdin/stdout/other globals.

### 4. All Decoded Messages

Extracted and decoded all fullwidth UTF-8 strings from .rodata:

```
0x12f0: ⚠️　Ｉｎｄｅｋｋｕｓｕ　ｗａ　ｍａｃｈｉｇａｔｔｅｉｍａｓｕ！
        (Index is wrong!)

0x14e0: 🗑️　Ｇｅｍｕ　ｗａ　ｓａｋｕｊｏ　ｓａｒｅｍａｓｈｉｔａ
        (The gem was deleted)

0x1ca8: ⚔️　Ｋｅｎ　ｗａ　ｋｏｗａｒｅｔｅ　ｓｈｉｍａｉｍａｓｈｉｔａ　:(
        (The sword broke :()

0x1d10: ❓　Ｇｅｍｕ　ｗｏ　ｓｈｉｙｏｕ　ｔｏ　ｓｈｉｔｅｉｍａｓｕ　ｋａ？：
        (What are you trying to do with the gem?:)
```

**Significant Absence:** No "upgrade", "complete", "perfect", or "success" (forging) messages found anywhere in binary.

### 5. Exit Points Analysis

Only 2 locations call exit():
1. `fail()` function at 0xc74: `call exit@plt` with exit code 0x520
2. `main()` at end: calls fail() then exit() - both unreachable if we could prevent them

```c
// main() end (simplified)
for (i = 0; i < 14; i++) {
    // ... operations ...
}
fail(&DAT_00101ca8);  // "sword broken" - ALWAYS executed
exit(0x520);           // ALWAYS executed
```

### 6. show() Function

```c
void show(void) {
    iVar2 = check_idx();
    puts((char *)(&buf)[iVar2]);  // Prints heap contents
}
```

Could potentially be used to leak data or print specific patterns.

---

## Analysis Tools Created

1. **check_memory_layout.sh** - Examines runtime memory mapping
   - Shows exact addresses of buf, stdin, stdout, heap
   - Confirms memory layout constraints

2. **compare_success_fail.sh** - Compares success/fail functions
   - Disassembles both functions
   - Identifies all call sites
   - Highlights the critical difference (exit vs return)

3. **examine_rodata.sh** - Extracts .rodata strings
   - Dumps full .rodata section
   - Searches for keywords (flag, success, upgrade, forge, sword)
   - Found only "success" in function name, no special strings

4. **decode_messages.py** - Decodes UTF-8 fullwidth text
   - Extracts and decodes all Japanese messages
   - Reveals actual text of all error/status messages
   - Confirms no hidden "upgrade" message exists

---

## Implications

### What We Can't Do
1. **Prevent the 14-operation limit** - Counter is on stack, protected by canary
2. **Overwrite stdin/stdout pointers** - They're before buf, NULL writes go forward only
3. **Bypass the final fail()** - It's hardcoded in main() after loop
4. **Find a "win" function** - Doesn't exist in binary
5. **Trigger a special message** - No "upgrade" or "success" strings exist

### What Remains Possible
1. **Heap corruption via NULL write** - Can corrupt tcache metadata
2. **Arbitrary allocation** - If tcache corrupted correctly
3. **Arbitrary write** - If we can control malloc return value
4. **Server-side detection** - Flag might be server-side, not in binary

### The Puzzle
With only 14 operations and mandatory `fail("sword broken")` at the end:
- How does "upgrading" differ from "breaking"?
- What heap state or output triggers flag delivery?
- What is the "outside the box" solution?

---

## Unanswered Questions

1. **Tcache exploitation path** - Can we corrupt tcache to get arbitrary write?
2. **Target for arbitrary write** - What would we write to achieve the goal?
3. **Server behavior** - How does server detect "upgrade" vs "broken"?
4. **The 0.7% solve rate** - What knowledge/technique did that one team use?

---

## Scripts Usage

```bash
# Check memory layout
./check_memory_layout.sh

# Compare success and fail functions
./compare_success_fail.sh

# Examine .rodata strings
./examine_rodata.sh

# Decode all messages
python3 decode_messages.py
```

---

**Conclusion:** Binary analysis is complete. All functions, strings, and behaviors are documented. The solution must involve heap exploitation (tcache corruption) or server-side logic that wasn't discoverable through static analysis alone.
