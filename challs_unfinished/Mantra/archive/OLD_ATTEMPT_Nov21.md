# Mantra Exploit Attempt

## Challenge Analysis
- **Category**: Pwn (Hard)
- **Difficulty**: 1000 points, 0 solves
- **Binary**: 64-bit ELF, PIE, Full RELRO, NX, Canary, SHSTK, IBT
- **libc**: 2.34 (Ubuntu)

## Vulnerability Identified
### Out-of-Bounds Read/Write in Heap Array

**Location**: `retie_bead()` and `recite_bead()` functions

**Root Cause**:
- Both functions accept a user-provided index without bounds checking
- `tie_beads()` HAS bounds check: `if (*param_1 < local_20) exit()`
- `retie_bead()` has NO bounds check on index
- `recite_bead()` has NO bounds check on index

**Code Analysis** (from Ghidra):
```c
void retie_bead(long param_1) {
    // ... stack setup ...
    printf("\nWhich bead will you retie? ");
    __isoc99_scanf(&DAT_001020e4, &local_18);  // Read index (signed long)
    printf("\nNew mantra for bead %lu (8 glyphs): ", local_18);
    __isoc99_scanf(&DAT_0010221f, local_18 * 8 + *(long *)(param_1 + 8));  // Write to beads[index]
    // NO CHECK if local_18 < num_beads!
}
```

## Exploitation Constraints

### Severe Limitations:
1. **recite_bead** can only be called **ONCE** (flag check at param_1+0x18)
2. **retie_bead** can only be called **TWICE** (counter check at param_1+0x14)
3. Each operation is 8 bytes only
4. Format string is ` %8c` - no null termination, no overflow

### What We Can Do:
- **1 arbitrary 8-byte read** from heap + (index * 8)
- **2 arbitrary 8-byte writes** to heap + (index * 8)
- Negative indices work (write backward from allocation)
- Very large indices work (write forward from allocation)

## Attempted Approaches

### 1. Direct Heap Metadata Corruption
**Attempt**: Write to negative indices to corrupt heap chunk headers
**Status**: Possible but need precise heap layout knowledge
**Blocker**: Unclear what to overwrite for exploitation

### 2. Libc Pointer Leak
**Attempt**: Allocate large chunks (>0x420 bytes) to get unsorted bin with libc pointers
**Status**: Testing various allocation sizes
**Blocker**: Need to find exact offset where libc pointers appear on heap after our allocation

### 3. Tcache Poisoning
**Attempt**: Overwrite tcache->next pointers to get arbitrary write
**Status**: Requires libc leak first (ASLR)
**Blocker**: Chicken-and-egg problem - need leak to know where to write

### 4. Heap Scanning for Flag
**Attempt**: Scan heap memory hoping flag is loaded somewhere
**Status**: Tested offsets -20 to +200
**Blocker**: No flag found in heap (likely read from file on-demand)

## Key Findings

### Heap Layout (local testing):
- Offset -1: `0x61` (chunk size field)
- Offset 0-9: Our bead data
- Offset 11: `0x20d11` (top chunk remainder size)

### Structure Layout (stack, 28 bytes total):
```c
struct prayer_cord {
    uint64_t num_beads;      // offset 0x00
    void **beads;            // offset 0x08 (heap pointer)
    uint32_t tied;           // offset 0x10
    uint32_t retied;         // offset 0x14 (max 2)
    uint32_t recited;        // offset 0x18 (max 1)
};
```

## Assumptions Made

1. **Assumption**: Libc pointers exist on heap after large allocations
   - **Validation Needed**: Test with allocations >= 132 beads (0x420 bytes)

2. **Assumption**: We can reach interesting memory with large positive/negative indices
   - **Validation**: Confirmed OOB works, but unclear what to target

3. **Assumption**: The challenge expects sophisticated heap exploitation
   - **Alternative**: Maybe there's a simpler bug we're missing?

4. **Assumption**: Flag needs to be exfiltrated via RCE or arbitrary read
   - **Alternative**: Could flag be accessible via simpler means?

## Next Steps to Try

1. **Systematic libc leak search**:
   - Test allocations: 132, 150, 200, 500, 1000 beads
   - Read at offsets: allocation_size + [0, 1, 2, 5, 10, 20, 50]
   - Look for addresses matching 0x7f____________

2. **House of Force** (if we can corrupt top chunk):
   - Write to offset that hits top chunk size
   - Make it very large (0xffffffffffffffff)
   - Trigger malloc to wrap around

3. **File Structure Exploit**:
   - Target stdout/stderr FILE structures
   - Use limited writes to corrupt vtable or flags
   - Trigger arbitrary read/write via file operations

4. **Alternative bug search**:
   - Re-examine all functions for other vulnerabilities
   - Check if there's an integer overflow we missed
   - Look for format string bugs in banner/menu

## Resources Needed
- Heap feng shui knowledge for glibc 2.34
- FILE structure exploitation techniques
- House of Force / House of techniques reference

## Key Findings Summary

### What Works
✅ Can read/write at any offset from heap allocation
✅ Negative indices work (can write to chunk headers)
✅ Very large indices work (can write far forward)
✅ Remote connection confirmed working (154.57.164.76:31856)

### What Doesn't Work
❌ No reliable libc pointer leak found on heap
❌ Flag not found in heap memory scan
❌ No obvious win function or backdoor
❌ Limited success with standard heap exploitation techniques

## Recommendations for Next Solver

This challenge appears to be genuinely difficult (0 solves, 1000 points). Possible paths forward:
- Research recent CTF writeups for similar constraints (1 read + 2 write primitives)
- Deep dive into glibc 2.34 heap internals and recent techniques
- Consider if there's a non-heap exploitation path
- Look for heap grooming techniques to position libc pointers reliably

## Time Invested
- Binary analysis: ~1 hour
- Exploitation attempts: ~3 hours
- Documentation: ~30 minutes

**Final Status**: **UNSOLVED** - Stuck on finding reliable libc leak or alternative exploitation path within severe primitive constraints
