# ForgottenVault - CTF Writeup

**Challenge:** ForgottenVault
**Category:** Reverse Engineering
**Difficulty:** Easy
**Points:** 975
**Flag:** `HTB{s1gN4l_H4ndL3r$-t0_w1n?}`

## Challenge Description
An ancient machine sealed deep within a vault beneath Kageno begins to hum, waiting for a master...

## Initial Analysis

The challenge provides a single ELF binary file called `forgotten_vault`. Running `file` on it reveals:
```
forgotten_vault: ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped
```

Running the binary prompts for a code:
```
Deep beneath Kageno, a forgotten vault stirs.
A rusted mechanism hums faintly, waiting for a code long lost.

Enter code>
```

## Vulnerability Discovery

### Binary Structure

Using `objdump` to disassemble the binary, I identified three key functions:

1. **`setup` (0x1200)** - Sets up a signal handler
2. **`check_pin` (0x1410)** - Performs arithmetic on user input
3. **`handler` (0x1290)** - Signal handler that decrypts and prints the flag

### Signal Handler Mechanism

The `setup` function registers a signal handler for **SIGFPE (signal 8)** - the floating-point exception signal, which is also triggered by integer division by zero:

```c
// Pseudocode
void setup() {
    struct sigaction sa;
    sa.sa_handler = handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGFPE, &sa, NULL);
}
```

### The check_pin Function

The `check_pin` function performs the following calculations on the user input:

```c
int check_pin(int input) {
    int numerator = input + 0x154f641;
    int denominator = (input - 0x4149) + (input + 0xac979988) + 1;
    int result = numerator / denominator;  // idiv instruction
    calculated = result;
    return;
}
```

The division operation (`idiv`) will trigger **SIGFPE** when the denominator is zero.

### The Decryption Handler

When SIGFPE is triggered, the `handler` function executes and:

1. Decrypts 44 bytes of encrypted data stored at address `0x4080`
2. Prints the decrypted message character by character
3. Calls `_exit(0)` to terminate the program

The decryption algorithm works backwards (from index 43 to 0) and applies the following transformations to each 16-bit value:

```python
for i in range(43, -1, -1):
    val = encrypted[i]
    val = val ^ 0x4d4c          # XOR
    val = rol32(val, 2)         # Rotate left 2 bits
    val = val ^ 0x4944          # XOR
    val = ror32(val, 5)         # Rotate right 5 bits
    val = (val - prev_char)     # Subtract previous character
    val = val & 0xff            # Keep only low byte
    decrypted[i] = val
    prev_char = val             # Update for next iteration
```

The initial `prev_char` value is `0x41` ('A').

## Exploitation

### Method 1: Calculate the Trigger PIN

To trigger SIGFPE, we need the denominator to equal zero:

```
(input - 0x4149) + (input + 0xac979988) + 1 = 0
2*input + 0xac979988 - 0x4149 + 1 = 0
2*input = 0x4148 - 0xac979988
2*input = -0xac975840
input = 699683808
```

Providing this input should trigger the signal handler and print the decrypted flag.

### Method 2: Static Decryption (Used)

Since the encrypted data is statically stored in the binary, we can extract and decrypt it manually:

1. Extract the encrypted data from address `0x4080` using `objdump`
2. Implement the decryption algorithm in Python
3. Decrypt all 44 bytes to reveal the flag

The encrypted data (44 16-bit little-endian values):
```
5a3d 592d 595d 59dd 582d 5b85 5c25 5ad5 5985 5965 580d 59d5
5955 5b9d 5d7d 5c5d 5bfd 5bad 5af5 586d 5a3d 5bdd 5ab5 5b0d
5a1d 5945 5a25 5cfd 5a0d 598d 5a9d 5ce5 5a35 5bad 5d95 5a15
5a3d 5b65 59ad 5a5d 5be5 5a75 5afd 5aed
```

Running the decryption script yields:
```
Access Granted, HTB{s1gN4l_H4ndL3r$-t0_w1n?}
```

## Key Techniques

1. **Signal Handler Analysis** - Understanding how SIGFPE is used to execute hidden code
2. **Division by Zero** - Calculating the input that triggers the exception
3. **Static Decryption** - Reversing the encryption algorithm to extract the flag without execution
4. **Assembly Analysis** - Reading x86-64 assembly to understand the binary logic

## Flag

`HTB{s1gN4l_H4ndL3r$-t0_w1n?}`

## Tools Used

- `file` - Binary identification
- `strings` - String extraction
- `objdump` - Disassembly and data extraction
- Python 3 - Decryption script development

## Solution Files

- [`decrypt_flag_v2.py`](decrypt_flag_v2.py) - Final decryption script
- [`calculate_pin.py`](calculate_pin.py) - PIN calculation script
