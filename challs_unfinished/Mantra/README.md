# Mantra - Neurogrid CTF 2025

## Challenge Information
- **Challenge ID**: 63264
- **Category**: Pwn (Hard)
- **Difficulty**: 1000 points
- **Solves**: 0 (as of 2025-11-23)
- **Status**: ❌ **UNSOLVED - Exhaustive Analysis Complete**
- **Analysis Time**: ~19 hours across 3 sessions
- **Server**: 154.57.164.75:30444 (Active - Restarted 2025-11-23)

## Description
> In the hush of the Shinju Shrine hangs an unfinished prayer cord — its beads empty, waiting to be tied with sacred words.
> Each bead remembers what is whispered into it, but the cord is old… and its threads fray easily.
> Those who tie too many knots say the cord begins to whisper back.

## Quick Start

### Current Status
This challenge remains unsolved after ~19 hours of comprehensive analysis. See [FINAL_COMPREHENSIVE_ANALYSIS.md](FINAL_COMPREHENSIVE_ANALYSIS.md) for complete details.

### Testing Scripts
```bash
# Verify remote connectivity
python verify_remote.py

# Compare local vs remote behavior
python remote_comparison_fixed.py

# Test exploitation theories
python test_exploitation_theories.py

# Test negative inputs
python test_negative_inputs.py

# Fuzzing suite
python fuzz_mantra.py
```

### Connection Details
- **Host**: 154.57.164.75
- **Port**: 30444
- **Status**: Active

## Directory Structure
```
Mantra/
├── mantra                      # Challenge binary
├── glibc/                      # Custom glibc 2.34
│   ├── ld-2.34.so
│   └── libc.so.6
├── README.md                   # This file
├── FINAL_COMPREHENSIVE_ANALYSIS.md  # Complete analysis
├── BLOCKERS.md                 # Blocker analysis
├── RESEARCH_SUMMARY.md         # Research findings
├── NEGATIVE_INPUT_ANALYSIS.md  # Negative input testing
├── INSTANCE_RESTART.md         # Instance restart log
├── testing/                    # Test scripts
│   ├── verify_remote.py        # Quick connectivity check
│   ├── remote_comparison_fixed.py  # Local vs remote
│   ├── test_exploitation_theories.py  # Exploitation tests
│   ├── test_negative_inputs.py  # Negative input tests
│   └── fuzz_mantra.py          # Fuzzing suite
└── archive/                    # Old/deprecated files
```

## Key Files
- **FINAL_COMPREHENSIVE_ANALYSIS.md** - Complete analysis (READ THIS FIRST)
- **BLOCKERS.md** - Detailed explanation of why exploitation is blocked
- **RESEARCH_SUMMARY.md** - Research on modern heap techniques (2023-2025)
- **NEGATIVE_INPUT_ANALYSIS.md** - Systematic negative input testing results

## Vulnerabilities Identified

### 1. Out-of-Bounds Heap Read
- **Function**: `recite_bead()`
- **Issue**: No bounds checking on user-provided index
- **Primitive**: Read 8 bytes at `beads[user_index]`
- **Constraint**: Can only be called **ONCE**

### 2. Out-of-Bounds Heap Write
- **Function**: `retie_bead()`
- **Issue**: No bounds checking on user-provided index
- **Primitive**: Write 8 bytes to `beads[user_index]`
- **Constraint**: Can only be called **TWICE**

## Key Findings

### Heap Layout (Confirmed via GDB)
```
Offset -1:  0x0000000000000331  <- Our chunk size
Offset  0:  [Bead 0 data]
...
Offset 99:  [Bead 99 data]       (for 100-bead allocation)
Offset 100: 0x0000000000000000  <- Top chunk prev_size
Offset 101: 0x0000000000020a41  <- Top chunk size ★
Offset 102: [Top chunk data]
```

### Exploitation Constraints
- **1 read + 2 writes** maximum (extremely limited primitives)
- Each operation is exactly 8 bytes (scanf format ` %8c`)
- No buffer overflow (format is properly length-limited)
- Beads array allocated via malloc() in `weave_cord()`
- `weave_cord()` can only be called **once**
- **No way to trigger malloc again** after initial allocation

## Critical Blocker

The fundamental blocker preventing exploitation:

**Cannot trigger malloc after corrupting heap metadata**

Even though we can:
- ✅ Corrupt top chunk size at offset 101
- ✅ Corrupt our own chunk metadata at offset -1
- ✅ Write to arbitrary heap offsets

We cannot:
- ❌ Trigger malloc to hit __malloc_assert
- ❌ Reach libc structures (stderr, __exit_funcs) from heap
- ❌ Create UAF or double-free primitives
- ❌ Find libc pointers in accessible heap regions

### Why Standard Techniques Don't Work

| Technique | Blocker |
|-----------|---------|
| House of Cat | Can't trigger malloc OR reach stderr |
| House of Corrosion | Need 10+ consecutive bytes (have 2×8 separate) |
| Tcache Poisoning | Need UAF/double-free (no free() function) |
| FILE Structure | stderr/stdout in libc, not heap |
| __exit_funcs | In libc, encrypted in glibc 2.34 |
| House of Force | Can corrupt top chunk, can't trigger malloc |

## Attempted Approaches

1. ✅ **Heap Layout Mapping** - Complete heap structure mapped via GDB
2. ✅ **Libc Leak Search** - Tested allocations from 10 to 1000 beads, no leaks found
3. ✅ **Flag Memory Search** - Searched offsets -50 to +1050, flag not in memory
4. ✅ **Top Chunk Corruption** - Can corrupt at offset 101, but can't exploit
5. ❌ **Malloc Trigger** - No way to call malloc after initial allocation
6. ❌ **Alternative Primitives** - No UAF, no free(), no secondary vulnerabilities found

## Research Conducted

### Techniques Investigated
- House of Cat (glibc 2.35)
- House of Corrosion (glibc 2.27)
- House of Botcake (glibc 2.26+)
- House of Force (pre-2.29)
- FILE structure exploitation
- __malloc_assert triggering
- Safe-linking bypass
- Tcache poisoning

### Resources Used
- [Overview of GLIBC heap exploitation techniques](https://0x434b.dev/overview-of-glibc-heap-exploitation-techniques/)
- [House of Corrosion](https://github.com/CptGibbon/House-of-Corrosion)
- [House of Cat - picoCTF 2024](https://pwn2ooown.tech/ctf/writeup/2024/06/10/picoCTF-HFT)
- [how2heap repository](https://github.com/shellphish/how2heap)
- [FILE Structure Exploitation](https://dhavalkapil.com/blogs/FILE-Structure-Exploitation/)
- [glibc malloc source](https://github.com/lattera/glibc/blob/master/malloc/malloc.c)

## Time Investment
- Binary analysis: 2 hours
- GDB debugging: 2 hours
- Ghidra decompilation: 0.5 hours
- Research: 3 hours
- Exploit attempts: 3 hours
- Integer overflow testing: 1 hour
- Stack analysis: 0.5 hours
- Extended testing (Session 2): 2.5 hours
  - Memory layout analysis
  - Offset scanning (-1000 to +100000)
  - Environment variable testing
  - Primitive sequence testing
  - Format string analysis
- Documentation: 1 hour
- **Total**: ~15.5 hours across 2 sessions

## Files in This Directory

### Documentation
- **README.md** - This file (overview and summary)
- **FINAL_STATUS.md** - Complete final status with all work done ⭐
- **ATTEMPT_2025-11-23.md** - Comprehensive attempt documentation (Nov 23)
- **BLOCKERS.md** - Detailed blocker analysis
- **OLD_ATTEMPT_Nov21.md** - Previous attempt from Nov 21
- **OLD_CURRENT_ATTEMPT.md** - Earlier analysis notes
- **OLD_README.md** - Original README

### Binaries & Libraries
- **mantra** - Challenge binary
- **glibc/** - Custom glibc 2.34 libraries

### Scripts
- **final_attempt.py** - Last exploitation attempt
- **test_offsets.py** - Offset testing utility
- **test_remote_behavior.py** - Remote server testing
- **check_memory_layout.py** - Memory layout analysis

### Session 1 Work (Nov 23 AM)
1. ✅ Complete heap layout mapped (GDB + pwndbg)
2. ✅ Binary fully decompiled (Ghidra MCP)
3. ✅ Integer overflow behavior tested (max/min values)
4. ✅ Stack-to-heap distance calculated (~5.8 trillion units)
5. ✅ Tested "tie many knots" hint (1000 beads, no special behavior)

### Session 2 Work (Nov 23 PM)
1. ✅ Negative offset scanning (-1000 to 0) for libc/arena structures
2. ✅ Large positive offset scanning (up to 100,000) for flag in memory
3. ✅ Binary-to-heap distance mapping (5.4 trillion units - unreachable)
4. ✅ Discovered chunk at offset -83 (size 0x291, contains zeros)
5. ✅ Top chunk corruption with various invalid sizes tested
6. ✅ Primitive sequence testing (different read/write orderings)
7. ✅ Allocation size edge cases (0, 1, 7, 8, 108, 128, 256, 512, 1024, 2048)
8. ✅ Format string vulnerability analysis (all confirmed safe)
9. ✅ MALLOC_CHECK_ and LD_DEBUG environment variable testing
10. ❌ No exploitable path found despite exhaustive testing

## Recommendations for Next Solver

1. **Use Ghidra/IDA Pro** for complete decompilation
2. **Test extreme edge cases** (very large/small offsets for integer overflow)
3. **Look for hidden vulnerabilities** - deeper reverse engineering
4. **Consult CTF experts** specializing in modern glibc exploitation
5. **Consider novel techniques** - may require 2024-2025 methods not yet documented
6. **Check for unintended solutions** - might be simpler than expected

## Conclusion

This challenge remains **UNSOLVED** after comprehensive analysis. The extremely limited primitives (1 read, 2 writes) combined with the inability to trigger malloc make it exceptionally difficult to exploit using known techniques.

The **0 solves and 1000 points** suggest this is either:
- Genuinely very difficult requiring expert knowledge
- Requires a novel technique not in public documentation
- Has a hidden vulnerability not yet discovered
- Benefits from collaborative solving

**Next Steps**: Consider expert consultation, team collaboration, or waiting for hints/first blood to validate approach.

---

**Last Updated**: 2025-11-23 10:30 UTC
**Attempt Status**: Exhaustive analysis complete (15.5 hours across 2 sessions), exploitation blocked
**See**: [FINAL_STATUS.md](FINAL_STATUS.md) for complete detailed findings
