# Mantra - HackTheBox Neurogrid CTF 2025

## Challenge Information
- **Challenge Name**: Mantra
- **Category**: Pwn
- **Difficulty**: Hard
- **Points**: 1000
- **Solves**: 0
- **Challenge ID**: 63264
- **Start Time**: 2025-11-21 08:51:00 UTC

## Description
In the hush of the Shinju Shrine hangs an unfinished prayer cord — its beads empty, waiting to be tied with sacred words.
Each bead remembers what is whispered into it, but the cord is old… and its threads fray easily.
Those who tie too many knots say the cord begins to whisper back.

## Files
- `mantra` - Binary executable
- `glibc/ld-2.34.so` - Dynamic linker
- `glibc/libc.so.6` - C library (version 2.34)
- `flag.txt` - Fake flag for local testing

## Vulnerability

**Out-of-Bounds Heap Read/Write**
- Location: `retie_bead()` and `recite_bead()` functions
- `retie_bead()`: Writes 8 bytes to `beads[user_index]` with NO bounds check
- `recite_bead()`: Reads 8 bytes from `beads[user_index]` with NO bounds check
- Both positive and negative indices work

## Exploitation Constraints

- **1 OOB read** maximum (recite_bead can only be called once)
- **2 OOB writes** maximum (retie_bead can only be called twice)
- Each operation is exactly 8 bytes

## Status

**UNSOLVED** - Challenge is very difficult (0 solves, 1000 pts)

See [ATTEMPT.md](ATTEMPT.md) for detailed analysis of approaches tried.
See [SUMMARY.md](SUMMARY.md) for work summary.
See [exploit_attempt.py](exploit_attempt.py) for current exploit code.
