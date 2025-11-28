# Codex of Failures - Solved ✅

**Status:** SOLVED
**Category:** Reversing
**Difficulty:** Hard
**Points:** 950
**CTF:** Neurogrid CTF 2025
**Flag:** `HTB{0bfUsC@t10n_w1tH_3rR0r5}`

## Quick Summary

Successfully solved by creating an LD_PRELOAD hook to capture errno values from intentionally failing syscalls in the binary's child process. The binary uses errno values as a validation key, which is then XOR'd with a hardcoded value to produce the flag.

## Solution

The binary validates a 28-character input by comparing each character against errno values from failing syscalls:

```
input[i] == chr(errno_function[i]() + 0x2f)
```

**Errno sequence:** `[2, 10, 6, 1, 2, 3, 4, 7, 6, 5, 8, 9, 2, 4, 7, 6, 10, 9, 8, 5, 6, 7, 4, 3, 2, 1, 4, 3]`

**Key:** `1950123654781365987456321032`

**Flag generation:** `flag[i] = key[i] XOR xor_key[i]`

## The "Outside the Box" Insight

The challenge description says *"each error it records is a lie that almost happened"* - this refers to how the binary **intentionally creates errors** by calling syscalls designed to fail:

- `setuid(0)` when not root → EPERM
- `open("/nonexistent")` → ENOENT
- `execve("/bin/true")` after filling memory → E2BIG
- etc.

These are deliberate failures, not real errors!

## Files

### Solution Files
- **errno_hook_v2.c** - LD_PRELOAD hook that captures errno values
- **errno_hook_v2.so** - Compiled hook library
- **extract_final_key.py** - Generates key and flag from errno values
- **SOLUTION.md** - Complete writeup with technical details

### Analysis Tools
- **parse_function_table.py** - Extracts 28-function sequence from binary

### Challenge Files
- **rev_codex_of_failures/** - Original binary (patched version available)
- **rev_codex_of_failures.zip** - Original download

## Quick Start

```bash
# Compile the hook
gcc -shared -fPIC errno_hook_v2.c -o errno_hook_v2.so -ldl

# Run with hook to capture errno values
echo "AAAAAAAAAAAAAAAAAAAAAAAAAAAA" | LD_PRELOAD=./errno_hook_v2.so ./rev_codex_of_failures/chall_patched

# Check captured errno values
cat /tmp/errno_log_v2.txt

# Generate and test the key
python3 extract_final_key.py

# Verify the flag
echo "1950123654781365987456321032" | ./rev_codex_of_failures/chall_patched
```

## Key Technique

**LD_PRELOAD Runtime Hooking:**
- Hook `fork()` to detect child process creation
- Hook `__errno_location()` to capture errno values
- Filter to only capture from child process (where validation happens)
- Avoid duplicate errno captures

---

**Solved:** 2025-11-22
**Technique:** Runtime errno hooking via LD_PRELOAD
