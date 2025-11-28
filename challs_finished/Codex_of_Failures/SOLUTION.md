# Codex of Failures - Complete Solution

**Challenge:** Codex of Failures (Reversing - Hard)
**CTF:** Neurogrid CTF 2025
**Status:** ✅ SOLVED
**Points:** 950
**Date Solved:** 2025-11-22
**Flag:** `HTB{0bfUsC@t10n_w1tH_3rR0r5}`

## Challenge Description

> When the ritual failed and the last flame died, the clan elders locked their shame inside a book of mistakes - the Codex of Failures. Each error it records is a lie that almost happened. You have found the codex locked behind a malevolent spell. Kuromaru's voice is hidden there; only by reading failures correctly can you force the ancient book to confess a secret vital to your journey's success.

## Solution Overview

The binary uses **intentionally failing syscalls** to generate errno values, which are then used as a validation key. By hooking errno at runtime using LD_PRELOAD, I extracted the correct 28 errno values and generated the flag.

## Binary Analysis

### Anti-Debug Protection
- Binary forks a child process and uses `ptrace(PTRACE_TRACEME)`
- Anti-debug check can be bypassed by NOP'ing the comparison at offset `0x4257`

### Validation Mechanism

The binary validates a 28-character input using this formula:

```c
for (i = 0; i < 28; i++) {
    errno_value = errno_function[i]();
    if (input[i] == chr(errno_value + 0x2f)) {
        continue;  // valid
    } else {
        fail();
    }
}
```

### Flag Generation

Once validation passes, the flag is generated via XOR:

```c
xor_key = [0x79, 0x6d, 0x77, 0x4b, 0x01, 0x50, 0x55, 0x63,
           0x46, 0x77, 0x77, 0x4c, 0x00, 0x03, 0x58, 0x6a,
           0x4e, 0x09, 0x43, 0x7c, 0x6a, 0x05, 0x41, 0x60,
           0x01, 0x42, 0x06, 0x4f]

for (i = 0; i < 28; i++) {
    flag[i] = input[i] XOR xor_key[i]
}
```

### The "Outside the Box" Insight

The challenge hint about "thinking outside the box" refers to how the binary **intentionally creates errors**:

- Each of the 28 validation functions calls a syscall designed to fail
- The errno value from the failed syscall is used as the expected input character
- "Each error it records is a lie that almost happened" - these are deliberate failures!

### Errno-Generating Functions

The binary uses 10 unique functions that generate errno values:

| Function | Syscall | Errno | Value |
|----------|---------|-------|-------|
| `FUN_00103493` | `setuid(0)` | EPERM | 1 |
| `FUN_001034aa` | `open("/nonexistent")` | ENOENT | 2 |
| `FUN_001034d0` | `kill(-0x21524111, 0x1a4)` | ESRCH | 3 |
| `FUN_001034ec` | `setitimer() + pause()` | EINTR | 4 |
| `FUN_001036e8` | `lseek() + read(/proc/self/mem)` | EIO | 5 |
| `FUN_00103886` | `open(unix_socket)` | ENXIO | 6 |
| `FUN_00103a9d` | `execve("/bin/true")` after memory fill | E2BIG | 7 |
| `FUN_00103bea` | `execve(exe_file)` without execute perms | EACCES | 13* |
| `FUN_00103c82` | `read(-1)` | EBADF | 9 |
| `FUN_00103ccc` | `waitpid(-1)` | ECHILD | 10 |

\* Note: Position 18 uses errno 8 (not 13) in the actual execution

## Solution Approach

### Step 1: Create LD_PRELOAD Hook

I created a custom shared library to intercept errno values:

```c
// errno_hook_v2.c
#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <dlfcn.h>
#include <unistd.h>

static FILE *logfile = NULL;
static int last_errno = -999;
static int is_child = 0;

pid_t fork(void) {
    static pid_t (*real_fork)(void) = NULL;
    if (!real_fork) {
        real_fork = dlsym(RTLD_NEXT, "fork");
    }

    pid_t result = real_fork();
    if (result == 0) {
        is_child = 1;
        logfile = fopen("/tmp/errno_log_v2.txt", "w");
        fprintf(logfile, "=== CHILD PROCESS START ===\n");
        fflush(logfile);
    }
    return result;
}

int *__errno_location(void) {
    static int *(*real_errno)(void) = NULL;
    static int read_count = 0;

    if (!real_errno) {
        real_errno = dlsym(RTLD_NEXT, "__errno_location");
    }

    int *ptr = real_errno();

    if (is_child && ptr && *ptr != 0 && *ptr != last_errno) {
        if (!logfile) {
            logfile = fopen("/tmp/errno_log_v2.txt", "w");
            setvbuf(logfile, NULL, _IONBF, 0);
        }
        fprintf(logfile, "[%d] errno = %d\n", read_count++, *ptr);
        fflush(logfile);
        last_errno = *ptr;
    }

    return ptr;
}
```

### Step 2: Compile and Run

```bash
gcc -shared -fPIC errno_hook_v2.c -o errno_hook_v2.so -ldl
echo "AAAAAAAAAAAAAAAAAAAAAAAAAAAA" | LD_PRELOAD=./errno_hook_v2.so ./rev_codex_of_failures/chall_patched
```

### Step 3: Extract Errno Values

The hook captured these 28 errno values:
```
[2, 10, 6, 1, 2, 3, 4, 7, 6, 5, 8, 9, 2, 4, 7, 6, 10, 9, 8, 5, 6, 7, 4, 3, 2, 1, 4, 3]
```

### Step 4: Generate Key

```python
errnos = [2, 10, 6, 1, 2, 3, 4, 7, 6, 5, 8, 9, 2, 4, 7, 6, 10, 9, 8, 5, 6, 7, 4, 3, 2, 1, 4, 3]
key = ''.join([chr(e + 0x2f) for e in errnos])
# Result: "1950123654781365987456321032"
```

### Step 5: Verify and Get Flag

```bash
echo "1950123654781365987456321032" | ./rev_codex_of_failures/chall_patched
# Output: HTB{0bfUsC@t10n_w1tH_3rR0r5}
```

## Key Insights

1. **System-Dependent Behavior**: The errno values are generated at runtime and can vary based on:
   - Kernel version
   - libc version
   - Process state (traced vs untraced)
   - Security policies

2. **Dynamic Analysis Required**: Static analysis alone cannot solve this challenge because:
   - The errno values depend on actual syscall execution
   - Different systems produce different errno values
   - The validation happens in a ptraced child process

3. **LD_PRELOAD is Powerful**: By hooking `__errno_location()` and `fork()`, we can:
   - Detect when the child process starts
   - Capture errno values as they're read
   - Avoid capturing parent process noise

## Files in This Directory

- **errno_hook_v2.c** - Working LD_PRELOAD hook (solution)
- **errno_hook_v2.so** - Compiled hook library
- **extract_final_key.py** - Script to generate key and flag from errno values
- **parse_function_table.py** - Extracts function sequence from binary
- **rev_codex_of_failures/** - Challenge files (binary)
- **rev_codex_of_failures.zip** - Original download
- **SOLUTION.md** - This file
- **README.md** - Quick reference

## Lessons Learned

1. Sometimes the "outside the box" solution is simpler than complex reverse engineering
2. LD_PRELOAD is extremely powerful for runtime hooking
3. System-dependent challenges require matching the target environment or dynamic analysis
4. Anti-debug can be bypassed but sometimes you don't need to defeat it - just work around it

---

**Challenge Solved:** 2025-11-22
**Technique:** Runtime errno hooking via LD_PRELOAD
**Difficulty:** Hard (but creative solution made it easier!)
