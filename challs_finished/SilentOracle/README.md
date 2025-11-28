# SilentOracle

**Challenge Name**: SilentOracle
**Category**: Reverse Engineering
**Difficulty**: Medium
**Date**: 2025-11-20 to 2025-11-21
**Points**: 975
**Solves**: Multiple (5+ at time of solve)
**Status**: ✅ SOLVED
**Flag**: `HTB{Tim1ng_z@_h0ll0w_t3ll5}`

## Description

Beneath the temple sits a mute sage: the Silent Oracle. It answers only in sighs and the faint click of the world around it. Most folk hear nothing - but those who learn to listen can read the pattern in the silence. Learn to listen to the silence, and the Oracle will whisper a secret of surviving in these cursed lands. Beware though, trying to lie to it will result in temporal banishment.

## Challenge Details

- **Challenge ID**: 63366
- **Flag ID**: 783621
- **Download**: `rev_silent_oracle.zip`
- **Binary**: `rev_silent_oracle/chall` (ELF 64-bit, stripped, PIE)

## Solution Summary

**See [WRITEUP.md](WRITEUP.md) for complete solution details.**

### ✅ Key Findings

- **Inverse Timing Oracle**: Wrong characters trigger 5s sleep (~6s response), correct characters are FAST (~0.7-1.5s)
- **Critical Discovery**: Flag does NOT start with `HTB{` in the comparison logic - this false assumption blocked previous attempts
- **Actual Flag**: `HTB{Tim1ng_z@_h0ll0w_t3ll5}` (28 characters, not 21)
- **Character Substitution**: Second 'i' in "Timing" is actually digit '1'
- **Extraction Method**: Character-by-character timing oracle with auto-selection when response < 2.0s

### 🔑 The Breakthrough

Previous attempts failed at position 4 because:
1. We assumed the flag started with `HTB{` in the comparison
2. When position 0 is wrong, ALL subsequent characters trigger the 5s sleep
3. Testing `"HTB{"` directly revealed it was FAST (0.72s), proving the assumption was wrong
4. Starting from position 0 and building character-by-character allowed successful extraction

## Documentation

- **[WRITEUP.md](WRITEUP.md)** - ✅ Complete solution writeup with methodology and lessons learned
- **[CRITICAL_DISCOVERY.md](CRITICAL_DISCOVERY.md)** - The breakthrough that solved the challenge
- **[BLOCKERS.md](BLOCKERS.md)** - Timeline of discoveries and blockers encountered
- **[FINDINGS.md](FINDINGS.md)** - Technical analysis and binary reverse engineering
- **[ATTEMPT.md](ATTEMPT.md)** - Previous attempt summary

## Solution Scripts

- **[extract_flag_interactive.py](extract_flag_interactive.py)** - ✅ Final working extraction script
- **[flag_result.txt](flag_result.txt)** - Extracted flag output
- **[test_timing_variants.py](test_timing_variants.py)** - Testing 'i' vs '1' substitutions

## Binary Analysis

- **[rev_silent_oracle/chall](rev_silent_oracle/chall)** - Challenge binary
- **[rev_silent_oracle/disasm.txt](rev_silent_oracle/disasm.txt)** - Full disassembly
