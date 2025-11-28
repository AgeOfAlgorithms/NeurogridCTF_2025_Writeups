# Mantra Challenge - Current Attempt (2025-11-23)

## Challenge Status
- **Challenge ID**: 63264
- **Difficulty**: Hard (1000 points)
- **Current Solves**: 0
- **Server**: 154.57.164.73:30861 (Active)
- **Attempt Status**: UNSOLVED

## Vulnerability Analysis

### Confirmed Vulnerabilities
1. **Out-of-Bounds Read** in `recite_bead()` - No bounds checking, can read any offset * 8 bytes
2. **Out-of-Bounds Write** in `retie_bead()` - No bounds checking, can write any offset * 8 bytes

### Exploitation Constraints (SEVERE)
- **1 OOB read maximum** - recite_bead can only be called ONCE
- **2 OOB writes maximum** - retie_bead can only be called TWICE
- Each operation is exactly 8 bytes (scanf format ` %8c`)
- No buffer overflow - format is properly length-limited

## Binary Analysis

### Security Mitigations
- Full RELRO
- Stack Canary
- NX
- PIE
- SHSTK/IBT enabled
- glibc 2.34 (no __malloc_hook/__free_hook/__realloc_hook)

### Key Functions
- `weave_cord()` - Allocates beads array (malloc), can only be called once
- `tie_beads()` - Writes to beads array with bounds checking
- `retie_bead()` - Writes to beads array WITHOUT bounds checking (max 2 calls)
- `recite_bead()` - Reads from beads array WITHOUT bounds checking (max 1 call)

### Scanf Format
- Format: ` %8c` (reads exactly 8 characters, no null termination)
- No buffer overflow possible

## Research Conducted

### Techniques Investigated

1. **House of Cat** ([Source](https://pwn2ooown.tech/ctf/writeup/2024/06/10/picoCTF-HFT))
   - Requires: corrupting stderr FILE structure + top chunk size + triggering malloc
   - **Blocker**: Can only call malloc once (in weave_cord), can't trigger again
   - **Blocker**: stderr is in libc data section, not reachable from heap OOB

2. **House of Corrosion** ([Source](https://github.com/CptGibbon/House-of-Corrosion))
   - Requires: at least 10 consecutive bytes of write via write-after-free
   - **Blocker**: We only have 2 separate 8-byte writes, not consecutive

3. **House of Botcake**
   - Requires: double-free or UAF to achieve tcache poisoning
   - **Blocker**: No free() primitive available

4. **FILE Structure Exploitation** ([Source](https://dhavalkapil.com/blogs/FILE-Structure-Exploitation/))
   - Requires: ability to corrupt FILE structures
   - **Blocker**: FILE structures (stdout/stderr) are in libc, not heap

5. **__exit_funcs Exploitation**
   - glibc 2.34 removed hooks, __exit_funcs is encrypted
   - **Blocker**: Need to know encryption key, structure not on heap

### Testing Results

#### Heap Layout Exploration
- Offset -1: `0x61` (chunk size field of our allocation)
- Offsets 0-299: Our bead data
- Offsets 300+: Mostly zeros (no libc pointers found)
- Tested allocation sizes: 10, 50, 100, 200, 300, 500, 1000 beads
- **Result**: No libc leaks found, no obvious exploitation path

#### Memory Search
- Searched offsets from -20 to +1050
- No flag strings found in accessible memory
- No libc addresses found in tested ranges
- No obvious heap addresses to leverage

## Blockers

### Primary Blockers
1. **Cannot trigger malloc after initial allocation**
   - Only one malloc call (weave_cord)
   - Can't trigger __malloc_assert without subsequent malloc
   - House of Cat requires malloc assertion

2. **Cannot reach libc structures from heap**
   - stderr, stdout in libc data section
   - __exit_funcs in libc
   - No pointers to these structures found on heap

3. **No UAF or double-free primitive**
   - No free() function exposed
   - Can't create dangling pointers
   - Tcache poisoning requires free chunks

4. **Extremely limited primitives**
   - 1 read + 2 writes is insufficient for known techniques
   - Can't chain multiple operations
   - Can't get feedback after writes

### Secondary Issues
- Safe-linking in glibc 2.34 requires heap leak for tcache poisoning
- No obvious way to leak heap addresses
- No way to leak flag file contents (not in memory)

## Attempts Made

### Attempt 1: Find Libc Leak
- Allocated large chunks (132, 256, 500, 1000 beads) hoping for unsorted bin
- Read at offsets past allocation
- **Result**: No libc pointers found

### Attempt 2: Top Chunk Corruption
- Tried to locate and corrupt top chunk size
- **Result**: Offset -1 has size field, but corrupting it doesn't help without malloc

### Attempt 3: Direct Flag Search
- Searched memory for flag patterns ("HTB{", "flag")
- **Result**: Flag not loaded in accessible memory

### Attempt 4: Heap Metadata Corruption
- Tried corrupting heap metadata at various offsets
- **Result**: No useful side effects without triggering malloc

## Theories on Solution

### Theory 1: Unknown Technique
- Maybe there's a recent 2024-2025 exploitation technique for glibc 2.34 with minimal primitives
- Could involve __exit_funcs or other glibc internals
- **Action Needed**: More research on cutting-edge heap techniques

### Theory 2: Stack Corruption
- Maybe OOB can reach stack somehow?
- **Counter**: Beads are heap-allocated, stack is far away

### Theory 3: Integer Overflow
- Maybe there's an integer overflow when computing offset * 8?
- Could allow wrapping to different memory regions
- **Action Needed**: Test very large positive/negative offsets

### Theory 4: Format String or Other Bug
- Maybe there's a secondary bug we haven't found?
- **Action Needed**: More thorough binary analysis with Ghidra

### Theory 5: Exit Path Exploitation
- When program exits, maybe we can corrupt exit handlers?
- **Counter**: __exit_funcs is encrypted in glibc 2.34

## Next Steps for Future Solver

1. **Use GDB with pwndbg/gef**
   - Interactive debugging to see exact heap layout
   - Find precise offsets to all heap structures
   - Test corruption effects in real-time

2. **Ghidra Analysis**
   - Decompile all functions
   - Look for secondary vulnerabilities
   - Understand exact scanf behavior

3. **Research Recent Techniques**
   - Look for 2024-2025 CTF writeups with similar constraints
   - Check for new glibc 2.34 exploitation methods
   - Consult with experienced CTF players

4. **Test Edge Cases**
   - Very large offsets (integer overflow?)
   - Negative offsets (underflow?)
   - Specific corruption patterns

5. **Consider Alternative Paths**
   - Is there a simpler bug being missed?
   - Is the challenge actually solvable?
   - Are there hints in the challenge description?

## Key Insight Needed

This challenge requires either:
- A novel exploitation technique not documented in standard resources
- A specific property of glibc 2.34 that enables exploitation with 1 read + 2 writes
- A secondary vulnerability that hasn't been identified
- Creative use of limited primitives in an unexpected way

The fact that it has 0 solves and 1000 points suggests it's either:
- Genuinely very difficult and requires expert knowledge
- Has a simple solution that everyone is overlooking
- May not be solvable without specific tools/environment

## Time Invested
- Research: ~2 hours
- Testing: ~1.5 hours
- Documentation: ~0.5 hours

## Resources Used
- [Overview of GLIBC heap exploitation techniques](https://0x434b.dev/overview-of-glibc-heap-exploitation-techniques/)
- [House of Corrosion](https://github.com/CptGibbon/House-of-Corrosion)
- [House of Cat - picoCTF 2024](https://pwn2ooown.tech/ctf/writeup/2024/06/10/picoCTF-HFT)
- [how2heap](https://github.com/shellphish/how2heap)
- [FILE Structure Exploitation](https://dhavalkapil.com/blogs/FILE-Structure-Exploitation/)
- [glibc malloc source](https://github.com/lattera/glibc/blob/master/malloc/malloc.c)

## Conclusion

**Status**: UNSOLVED

This challenge appears to be genuinely difficult or may require a specific insight/technique that hasn't been discovered yet. The extremely limited primitives (1 read, 2 writes) make it challenging to apply standard heap exploitation techniques.

Recommendation: This challenge may benefit from collaborative solving or consultation with CTF experts who have experience with cutting-edge glibc exploitation.
