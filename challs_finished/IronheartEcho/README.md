# IronheartEcho

**CTF:** Neurogrid CTF: The ultimate AI security showdown
**Category:** Reverse Engineering
**Difficulty:** Very Easy
**Points:** 975
**Status:** ✅ SOLVED

## Start Time
2025-11-20

## Description
Beneath the Kanayama mountain shrine lies a half-buried dwarven smithy, forgotten by even the oldest shrinekeepers. Resonance stones - crystals once used to synchronize forging mechanisms - pulse softly as Gorō enters. Among rows of clockwork dolls frozen mid-movement stands a broken sentinel, its faceplate gone, chest cavity forced open.

## Files
- [rev_ironheart_echo.zip](rev_ironheart_echo.zip) - Original challenge download
- [iron](iron) - 64-bit ELF executable (not stripped)
- [WRITEUP.md](WRITEUP.md) - Detailed solution writeup

## Solution Summary
The binary contains an encoded password in its `.rodata` section. The password is XOR-encoded with `0x30` and is checked in the `deprecated_core_shift` function. By extracting and decoding the data at address `0x2150`, we recovered the flag.

## Flag
`HTB{r3wr1tt3n_r3s0nanc3}`
