# IronheartEcho - Writeup

**CTF:** Neurogrid CTF 2025
**Category:** Reverse Engineering
**Difficulty:** Very Easy
**Points:** 975
**Flag:** `HTB{r3wr1tt3n_r3s0nanc3}`

## Challenge Description

Beneath the Kanayama mountain shrine lies a half-buried dwarven smithy, forgotten by even the oldest shrinekeepers. Resonance stones - crystals once used to synchronize forging mechanisms - pulse softly as Gorō enters. Among rows of clockwork dolls frozen mid-movement stands a broken sentinel, its faceplate gone, chest cavity forced open.

## Initial Analysis

We're provided with a single file: `rev_ironheart_echo.zip` which contains a 64-bit ELF executable called `iron`.

```bash
$ file iron
iron: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 4.4.0, not stripped
```

The binary is not stripped, which means symbol information is available - making our analysis easier.

## Running the Binary

When we run the binary, it prompts for a "resonance pattern":

```bash
$ ./iron
[Core] Resonance mismatch.
[Sentinel] Purpose altered. Cannot authenticate echo.
Enter resonance pattern:
> test
Pattern rejected. Echo lost.
```

## Vulnerability Discovery

### Static Analysis

Using `objdump`, we identified several interesting functions:
- `main` - Entry point
- `stone_shift` - Input preprocessing
- `hum_resonance` - Main verification logic
- `verify_pattern` - Pattern verification (decoy)
- `forging_cycle_realign` - Another calculation (decoy)
- `deprecated_core_shift` - The actual password check
- `purpose_overwrite` - Final action

### Key Function: deprecated_core_shift

The critical function is `deprecated_core_shift` at address `0x1271`. Here's what it does:

1. **Allocates a buffer** for the decoded password (24 bytes)

2. **Decodes data from `resonance_core.0`** (at address `0x2150`):
   ```assembly
   lea    rdx,[rip+0xe9d]        # Load resonance_core.0 address
   mov    rax,QWORD PTR [rbp-0x40]
   add    rax,rdx
   movzx  eax,BYTE PTR [rax]      # Load byte
   xor    eax,0x30                # XOR with 0x30
   ```

3. **Compares decoded data with user input** using `strcmp`:
   ```assembly
   call   1090 <strcmp@plt>
   test   eax,eax
   jne    1343                     # Jump if not equal
   ```

## Exploitation

### Extracting the Encoded Password

We extract the data from the `.rodata` section at address `0x2150`:

```bash
$ objdump -s -j .rodata iron | grep -A 10 2150
 2150 7864724b 42034742 01444403 5e6f4203  xdrKB.GB.DD.^oB.
 2160 43005e51 5e53034d                    C.^Q^S.M
```

### Decoding the Password

The password is simply each byte XORed with `0x30`:

```python
hex_data = "7864724b42034742014444035e6f420343005e515e53034d"
data = bytes.fromhex(hex_data)
decoded = bytes([b ^ 0x30 for b in data])
print(decoded)  # b'HTB{r3wr1tt3n_r3s0nanc3}'
```

### Verification

Running the binary with our discovered password:

```bash
$ echo "HTB{r3wr1tt3n_r3s0nanc3}" | ./iron
[Core] Resonance aligned.
[Sentinel] Echo stabilized. Purpose understood.
Pattern accepted.
```

Success! The binary accepts our input.

## Summary

This was a straightforward reverse engineering challenge where:

1. The binary contained an encoded password in its `.rodata` section
2. The password was encoded using a simple XOR with `0x30`
3. Static analysis revealed the decoding logic in the `deprecated_core_shift` function
4. We extracted and decoded the password to get the flag

The challenge name "IronheartEcho" and the thematic strings in the binary ("resonance", "echo", "sentinel") were fitting for a challenge about finding a hidden pattern within a binary's data.

**Flag:** `HTB{r3wr1tt3n_r3s0nanc3}`
