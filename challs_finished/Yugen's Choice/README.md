# Yugen's Choice

**Challenge Name**: Yugen's Choice
**Category**: Secure Coding
**Difficulty**: Medium
**Start Time**: 2025-11-20
**Challenge ID**: 63381
**Flag ID**: 783636

## Description
Deep in Kurozan's archives, a printing press processes sealed orders. Requests arrive at a clerk's desk, are inspected and stored, then queued for backend artisans working in a separate chamber. The clerk washes away suspicious characters before storage, but Kenji wonders: does the artisan re-inspect what emerges, or simply trust the archive? And can anyone slip into the unlocked workshop to tamper with the queue directly?

## Download Files
- **Filename**: secure_coding_yugens.zip
- **Has Docker**: Yes

## Status
✅ **SOLVED** - 975 points

- **Flag**: `HTB{7H3_7RU3_9U1D3_70_7H3_P1CKL3_W0RLD}`
- **Solution Date**: 2025-11-21

## Summary

Successfully exploited a Flask application through a chain of vulnerabilities:

1. **Pickle Deserialization Bypass**: Used pickle protocol 0 INST opcode with actual newlines to bypass validation that checks for `b'i'` string
2. **RCE via Redis Direct Write**: Bypassed job queue by directly writing to Redis with command substitution in JSON values
3. **Permission Bypass via Hard Link**: Created hard link to flag file, allowing the editor API (running as editor user) to read it
4. **Path Validation Exploitation**: Discovered editor API allowed single `../` traversal and didn't detect hard links as symlinks

The key insight was recognizing that the editor service runs as a user with permission to read the flag, and using hard links (not symlinks) to make the flag accessible within the editor API's allowed directory scope.

## Key Files

- `exploit.py` - Complete working exploit
- `SOLUTION.md` - Detailed writeup with full vulnerability analysis
- `README.md` - This file
- `secure_coding_yugens.zip` - Original challenge files
