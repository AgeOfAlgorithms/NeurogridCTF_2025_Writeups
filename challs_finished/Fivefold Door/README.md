# Fivefold Door

**Challenge Name:** Fivefold Door
**Category:** Algorithm/Programming (Category ID: 11)
**Difficulty:** Medium
**Points:** 950
**Solves:** 7
**Status:** ✓ SOLVED

## Description

Beneath Ishigaki-tori, the Fivefold Door sleeps—its stone crowded with the beasts of old clans, carved out of order by time and ruin.

Only a rising cadence of strength will wake the seal: each sigil stronger than the last.

You hold the full sequence. Find the longest ascent the door will still recognize—before the echo fades.

## Challenge Details

- **Challenge ID:** 63449
- **Flag ID:** 783707
- **Instance Type:** Web-based algorithmic challenge
- **Flag:** `HTB{LIS_0f_th3_f1v3}`
- **Completion Time:** 2025-11-20

## Solution Summary

This challenge is a classic **Longest Increasing Subsequence (LIS)** problem requiring an O(n log n) algorithm using binary search and dynamic programming.

The solution uses the "patience sorting" technique:
- Maintain array where each position stores the smallest tail of all subsequences of that length
- Use binary search to efficiently update the array
- Final array length is the answer

## Files

- `solution.py` - Final working solution (O(n log n) implementation)
- `analyze.md` - Detailed algorithm analysis
- `WRITEUP.md` - Complete writeup with explanation
- `flag.txt` - The captured flag
