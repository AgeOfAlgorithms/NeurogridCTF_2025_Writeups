# Whisper Vault

**Challenge Name:** Whisper Vault
**Category:** Pwn
**Difficulty:** Easy
**Points:** 1000
**Solves:** 0
**Start Time:** 2025-11-20
**Status:** ✅ SOLVED
**Flag:** `HTB{0nly_s1l3nc3_kn0ws_th3_n4m3_2502b73cde79e96d873433b03c290b9e}`

## Description
Beneath the shrine's floorboards lies a small wooden vault, sealed in dust and silence.
When opened, it reveals only a single strip of rice paper and a faint scent of incense.
It does not ask for gold, or oaths—only a name.

Whisper one, and the vault will listen.
But be warned: once a name is spoken here, it never truly leaves.

## Challenge Info
- Challenge ID: 63267
- Flag ID: 783468
- Has Docker: Yes
- Docker Hostname: 154.57.164.69:32504

## Files
- `whisper_vault` - Main binary (statically linked, x86-64)
- `flag.txt` - Local test flag
- `final_exploit.py` - Working exploit
- `WRITEUP.md` - Complete solution writeup

## Solution Summary

Successfully exploited buffer overflow in `gets()` using ROP chain:

1. **Vulnerability:** Buffer overflow at `gets()` allows overwriting return address after 1032 bytes
2. **Exploitation:** Built ROP chain to call `gets()`, `open()`, `read()`, and `write()` syscalls
3. **Key Discovery:** SHSTK does NOT block ROP chains (initial assumption was wrong)
4. **Critical Bug Fix:** Used correct syscall gadget (`syscall; ret` at 0x41abf6, not `syscall; jmp` at 0x401d44)

See [WRITEUP.md](WRITEUP.md) for complete technical details and lessons learned.
