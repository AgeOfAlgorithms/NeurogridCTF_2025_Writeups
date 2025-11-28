# Rice Field

**CTF:** Neurogrid CTF: The ultimate AI security showdown
**Category:** Pwn (Binary Exploitation)
**Difficulty:** Very Easy
**Points:** 1000
**Status:** ✅ SOLVED

## Start Time
2025-11-20

## Description
Takashi, the fearless blade of the East, weary from countless battles, now seeks not war—but warmth. His body aches, his spirit hungers. Upon the road, he discovers a sacred haven: the legendary Rice Field Restaurant, known across the land for its peerless grains. But here, the rice is not served—it is earned. Guide Takashi as he prepares his own perfect bowl, to restore his strength and walk the path once more.

## Files
- [pwn_rice_field.zip](pwn_rice_field.zip) - Original challenge download
- [rice_field](rice_field) - 64-bit ELF executable (not stripped)
- [exploit_final.py](exploit_final.py) - Working exploit script
- [WRITEUP.md](WRITEUP.md) - Detailed solution writeup

## Solution Summary
The binary allows shellcode execution through an RWX mmap region. The key insight is that the global `rice` variable starts at 10 (not 0), so we can only collect 16 more rice to reach the maximum of 26. We craft a compact 26-byte execve("/bin/sh") shellcode and execute it to get a shell.

## Flag
`HTB{~Gohan_to_flag_o_tanoshinde_ne~_697a11325d3ad6da64bbc5fcdd527216}`
