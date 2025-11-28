# Mantra Challenge - Attempt Documentation

## Challenge Information
- **Name:** Mantra
- **Category:** Pwn
- **Difficulty:** Hard
- **CTF:** Neurogrid CTF 2025 (HackTheBox)
- **Status:** Unsolved

## Binary Analysis

### Security Mitigations
- **RELRO:** Full RELRO (no GOT overwrite possible)
- **Canary:** Enabled (stack protection)
- **NX:** Enabled (no shellcode execution)
- **PIE:** Enabled (address randomization)
- **SHSTK/IBT:** Enabled (Intel CET features)
- **glibc:** 2.34 (no malloc_hook/free_hook)

### Binary Structure
The binary implements a "prayer cord" data structure with the following operations:

```c
struct cord {
    size_t count;      // offset 0x0 - number of beads
    void **beads;      // offset 0x8 - array of bead pointers
    int tied;          // offset 0x10 - flag indicating beads are tied
    int retie_count;   // offset 0x14 - number of retie operations (max 2)
    int recited;       // offset 0x18 - flag indicating a bead was recited
};
```

### Functions

1. **weave_cord** (0x131a)
   - Allocates beads array: `malloc(count * 8)`
   - No validation beyond checking if cord already exists

2. **tie_beads** (0x13cf)
   - **VULNERABILITY 1:** Uses `scanf("%s", &beads[i])` without length limit
   - Reads mantras directly into the beads pointer array
   - Allows heap buffer overflow

3. **retie_bead** (0x1523)
   - Allows rewriting a single bead
   - Limited to 2 operations (retie_count <= 1)
   - Same scanf vulnerability as tie_beads

4. **recite_bead** (0x161e)
   - **VULNERABILITY 2:** No bounds checking on index
   - Calls `fwrite(&beads[index], 8, 1, stdout)`
   - Allows out-of-bounds read for information leaking

## Identified Vulnerabilities

### Primary Vulnerability: Heap Buffer Overflow in tie_beads
The function uses `scanf("%s", &beads[i])` which writes user input directly into the beads array without any length validation. The description mentions "eight-glyph mantras" suggesting 8-byte strings, but no validation enforces this limit.

**Exploitation Potential:**
- Write beyond allocated heap chunk
- Corrupt adjacent heap metadata
- Overwrite tcache/fastbin structures
- Create fake chunks for exploitation

### Secondary Vulnerability: OOB Read in recite_bead
The recite_bead function doesn't validate the index parameter before accessing beads[index]. This allows reading arbitrary offsets from the beads array base address.

**Exploitation Potential:**
- Leak heap addresses
- Leak libc addresses (if can reach GOT or other pointers)
- Leak stack addresses (if stack pointers are nearby)
- Bypass ASLR/PIE

## Assumptions and Decisions

###Assumption 1: Scanf behavior with whitespace
**Decision:** Scanf("%s") stops at whitespace but will write as many bytes as provided up to that point
**Rationale:** Standard scanf behavior
**Validation:** Testing showed long strings cause heap corruption and multi-bead writes

### Assumption 2: Heap layout after weave_cord
**Decision:** The beads array is allocated on the heap adjacent to other malloc'd chunks or metadata
**Rationale:** Standard glibc heap allocator behavior
**Validation:** Overflow appears to affect subsequent operations, suggesting metadata corruption

### Assumption 3: Need for heap leak before exploitation
**Decision:** Must leak heap addresses to bypass safe-linking in glibc 2.34
**Rationale:** Tcache and fastbin pointers are XOR'd with heap base >> 12
**Validation:** Research on glibc 2.34 exploitation techniques confirms this requirement

### Assumption 4: Exploitation technique - FILE structure attack
**Decision:** Target stdout/stderr FILE structures for code execution
**Rationale:** Malloc hooks removed in glibc 2.34, FILE structure attacks still viable
**Validation:** Modern CTF writeups show FILE structure attacks work on recent glibc

### Assumption 5: Multi-stage exploitation required
**Decision:** Need multiple interactions: leak addresses, then exploit
**Rationale:** PIE + ASLR + safe-linking require address leaks before exploitation
**Validation:** All modern exploitation techniques for hardened binaries require leaks

## Attempted Exploitation Strategies

### Strategy 1: Direct Heap Overflow
**Approach:** Overflow beads array to corrupt adjacent chunks
**Execution:** Created exploit attempting to overflow with long strings
**Result:** Binary crashes or connection closes
**Blocker:** Without interactive debugging, difficult to craft precise heap layout

### Strategy 2: OOB Read for Address Leaks
**Approach:** Use recite_bead with large index to leak heap/libc addresses
**Execution:** Attempted to read negative or large indices
**Result:** Need to determine correct offsets to reach useful pointers
**Blocker:** Requires knowledge of exact heap layout at runtime

### Strategy 3: Tcache Poisoning
**Approach:** Corrupt tcache metadata to get arbitrary write
**Execution:** Research into glibc 2.34 tcache poisoning with safe-linking bypass
**Result:** Requires heap leak first (see Assumption 3)
**Blocker:** Complex multi-stage attack requiring precise heap manipulation

### Strategy 4: House of IO / FILE Attack
**Approach:** Use heap overflow to corrupt FILE structures (stdout/stderr)
**Execution:** Researched FILE structure exploitation for glibc 2.34
**Result:** Requires multiple leaks (libc, heap) and precise corruption
**Blocker:** High complexity for automated exploitation without interactive debugging

## Technical Challenges Encountered

### Challenge 1: Automation of Heap Exploitation
Heap exploitation requires understanding the exact runtime layout of heap chunks, which varies based on:
- Previous allocations
- Memory alignment
- glibc internal state
- ASLR randomization

Without interactive debugging (GDB with pwndbg/gef), it's extremely difficult to craft a reliable exploit.

### Challenge 2: glibc 2.34 Protections
Modern glibc has multiple protections:
- Safe-linking (XOR'ed pointers)
- Removed malloc hooks
- Tcache key validation
- Enhanced metadata checks

Each protection requires specific bypass techniques that are difficult to chain without trial-and-error testing.

### Challenge 3: Full Exploit Mitigation Stack
The combination of:
- Full RELRO
- PIE
- Canary
- NX
- SHSTK/IBT

Makes exploitation extremely challenging, requiring:
1. Information leaks (multiple addresses)
2. Heap manipulation (tcache/fastbin)
3. Control flow hijacking (FILE structures or other techniques)

### Challenge 4: Limited Interaction Window
Testing showed the binary crashes or closes connection after heap corruption, limiting the number of operations available for exploitation.

## What Would Be Needed to Solve

### Required Steps:
1. **Interactive Debugging Session**
   - Use GDB with pwndbg to examine heap layout after weave_cord
   - Identify exact offsets to useful structures (tcache header, other chunks)
   - Determine overflow size needed to reach and corrupt specific metadata

2. **Address Leak Development**
   - Use OOB read to find heap address (via tcache fd pointers)
   - Use heap leak to calculate libc base (via main_arena or unsorted bin)
   - Use libc leak to find system/one_gadget addresses

3. **Exploitation Primitive**
   - Craft tcache poisoning attack using leaked addresses
   - OR corrupt FILE structure to gain code execution
   - OR use largebin attack for arbitrary write

4. **Payload Delivery**
   - Chain all steps together in reliable exploit
   - Handle timing and state management
   - Execute final payload (ROP chain, one_gadget, or shellcode)

### Manual Testing Needed:
- Determine exact overflow sizes that don't immediately crash
- Find correct OOB read indices for leaks
- Test heap layout consistency across multiple runs
- Verify exploit reliability

## Conclusion

This is a **hard** pwn challenge that requires:
- Deep understanding of glibc 2.34 heap internals
- Experience with modern exploitation techniques (House of IO, tcache poisoning)
- Interactive debugging capability
- Multiple iterations of trial-and-error testing

The vulnerabilities are clear (heap overflow + OOB read), but exploitation requires precise heap manipulation that is difficult to automate without interactive debugging access.

**Recommendation:** This challenge would benefit from:
1. Manual debugging session with GDB to understand heap layout
2. Research into specific glibc 2.34 exploitation patterns
3. Possibly consulting recent CTF writeups for similar challenges
4. Interactive development and testing of exploit primitives

## Files Created
- `README.md` - Challenge documentation
- `analyze.py` - Initial analysis script
- `test_vuln.py` - Vulnerability verification
- `exploit.py` - First exploitation attempt
- `exploit2.py` - OOB read testing
- `simple_test.py` - Remote interaction testing
- `ATTEMPT.md` - This document
