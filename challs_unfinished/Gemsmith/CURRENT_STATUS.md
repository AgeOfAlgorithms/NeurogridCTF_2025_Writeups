# Current Exploitation Status

**Date:** 2025-11-23 20:15
**Focus:** Exploiting via delete() function based on user hint

## User's Hint
> "so you want to get to delete() then"

This suggests delete() is the key exploitation primitive.

## Why delete() is Critical

From GDB analysis:
```c
void delete(void) {
    check_idx();
    success(&DAT_001014e0);  // ← Doesn't exit! Returns normally
    free((void *)(&buf)[iVar2]);
    return;
}
```

**Key differences:**
- `delete()` → `success()` → return (continues execution)
- Other errors → `fail()` → exit(0x520) (terminates)

## Current Blockers

1. **Testing Issues**: Having trouble getting local tests to complete 14 operations cleanly
   - Tests keep hitting "invalid choice" error
   - Not seeing the final "sword broken" message
   - May be input formatting issue

2. **CTF Ended**: Neurogrid CTF 2025 ended Nov 23, can't test on live server

3. **Unclear Exploitation Path**: Multiple possibilities:
   - Simple pattern (call delete() X times)?
   - Tcache poisoning → arbitrary write?
   - Control flow hijacking to success()?
   - Server-side pattern detection?

## Potential Exploitation Vectors

### Vector 1: Tcache Poisoning
```
1. Alloc chunk A
2. Delete chunk A (UAF - buf[0] still points to freed chunk)
3. Alloc with specific byte count → NULL write corrupts tcache->next
4. Next alloc returns controlled address
5. Arbitrary write primitive
```

### Vector 2: Information Leak
```
1. Alloc chunk
2. Delete chunk (now in tcache)
3. Show() - should print tcache metadata (heap pointers)
   Problem: Can't get show() to output anything in tests
```

### Vector 3: Pattern-Based
```
Maybe the solution is simpler:
- Call delete() (success()) a specific number of times?
- Specific sequence of operations?
- Leave heap in specific state?
```

## What We Know Works

✓ delete() can be called (calls success, doesn't crash)
✓ UAF exists (buf[0] not NULLed after delete)
✓ NULL write works (confirmed in previous tests)
✓ Only index 0 is valid (can't use negative indices)

## What Doesn't Work

✗ Backward NULL writes (stdin/stdout before buf in memory)
✗ GOT overwrites (Full RELRO)
✗ Negative indices (rejected by check_idx)
✗ Multiple simultaneous allocations (only 1 slot: buf[0])

## Next Steps

Need to:
1. Fix local testing to properly see 14-operation completion
2. Test tcache corruption with different byte counts systematically
3. Verify if show() can leak heap addresses
4. Try different operation sequences (all delete, alternating, etc.)
5. Consider if solution is simpler than complex heap exploitation

## Files Created This Session

- exploit_strategy.md - Exploitation brainstorming
- test_double_free.sh - Double-free testing
- test_uaf_show.sh - UAF + show testing
- test_multiple_deletes.sh - Multiple success() calls
- test_tcache_leak.sh - Tcache metadata leak
- exploit_via_delete.py - Main exploitation attempt (pwntools)

**Status:** BLOCKED on testing issues, need working 14-operation test case to proceed
