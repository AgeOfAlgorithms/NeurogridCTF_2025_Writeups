# Manual

**Challenge Name:** Manual
**Category:** Forensics
**Difficulty:** Very Easy
**Start Time:** 2025-11-20 14:04 UTC
**Creator:** makelaris
**Status:** ✅ SOLVED
**Points:** 975
**Flag:** `HTB{34dsy_d30bfusc4t10n_34sy_d3t3ct10n}`

## Description

When a courier is found ash-faced on the cedar road, Shiori discovers a "tradesman's manual" folded in his sleeve, plain instructions on the outside, but inside a strange script of symbols and percent signs meant for a machine. The scroll is an obfuscated BAT attachment in disguise, a batch charm that only reveals its purpose once its knots are untied. Follow Shiori's lead: de-tangle the lines, read what the script truly does, and trace where its "manual" tries to send the unwary. In the shadows of Kageno, even a simple instruction sheet can open a door.

## Files

- `forensics_manual.zip` - Original challenge download
- `tradesman_manual.bat` - Obfuscated batch file (challenge artifact)
- `solution_deobfuscate.py` - Working deobfuscation script
- `extracted_payload.ps1` - Decoded PowerShell payload containing the flag

## Objective

De-obfuscate a batch (BAT) file to understand what it does and find the flag.

## Solution Summary

The batch file uses variable name obfuscation, base64 encoding, and separator injection (`djlrttmeqqkr`) to hide a PowerShell payload. The key breakthrough was realizing that the concatenated variables form a **complete PowerShell command** (not raw base64), from which the `$s` variable must be extracted and decoded separately as UTF-16 LE. The flag appears in the decoded PowerShell as part of a C2 URL: `http://malhq.htb/HTB{...}`

**See [WRITEUP.md](WRITEUP.md) for complete technical details and solution methodology.**
