# Mantra

**Category:** Pwn
**Difficulty:** Hard
**Start Time:** 2025-11-20 16:59 UTC

## Description
In the hush of the Shinju Shrine hangs an unfinished prayer cord — its beads empty, waiting to be tied with sacred words. Each bead remembers what is whispered into it, but the cord is old… and its threads fray easily. Those who tie too many knots say the cord begins to whisper back.

## Files
- `mantra` - Main executable
- `glibc/` - Custom glibc directory
- `flag.txt` - Flag file (dummy for local testing)

## Challenge ID
63264

## Status
**Unsolved** - Challenge requires interactive debugging for precise heap exploitation.

## Vulnerabilities Identified
1. **Heap Buffer Overflow** - `scanf("%s")` in tie_beads allows unbounded writes
2. **Out-of-Bounds Read** - recite_bead has no index validation

## Exploitation Approach
- Leak heap address via OOB read or tcache corruption
- Leak libc address via main_arena or unsorted bin
- Use tcache poisoning or FILE structure attack for code execution

## Files
- `mantra` - Challenge binary
- `glibc/` - Custom glibc 2.34 libraries
- `ATTEMPT.md` - Detailed analysis and findings
- `exploit_framework.py` - Exploitation framework (incomplete)
- `simple_test.py` - Simple remote interaction test

## Notes
This is a hard pwn challenge requiring:
- Deep glibc 2.34 heap internals knowledge
- Interactive debugging (GDB + pwndbg/gef)
- Modern exploitation techniques (House of IO, tcache poisoning)
- Multiple iterations of trial-and-error testing

See ATTEMPT.md for complete analysis.
