# Challenge Analysis

## Problem Statement

Determine if a sequence of drum beats can be formed by repeating a smaller prefix pattern.

**Input:**
- First line: N (length of sequence)
- Second line: N space-separated integers representing beats

**Output:**
- "YES" if the sequence is a repeating pattern
- "NO" otherwise

## Examples

**Example 1:**
- Input: `6` beats: `2 1 2 1 2 1`
- Pattern: `[2, 1]` repeats 3 times
- Output: `YES`

**Example 2:**
- Input: `10` beats: `4 2 4 2 3 4 1 6 10 7`
- No repeating pattern found
- Output: `NO`

## Solution Approaches

### 1. KMP Failure Function Approach
The KMP algorithm's failure function can detect if a string is periodic. If the length is divisible by `(n - failure[n-1])`, then the string has a repeating pattern.

### 2. Brute Force Approach
Try all possible prefix lengths that divide N evenly:
- For each divisor d of N
- Check if the first d elements repeat to form the entire sequence

### 3. String Doubling Trick
If a sequence S is formed by repeating pattern P:
- `S + S` will contain S at position `len(P)`
- Or equivalently, check if `S[0:n] == S[i:i+n]` for some i < n

## Algorithm Choice

I'll use the **brute force approach** as it's simple, clear, and efficient for this problem:
- Time complexity: O(N * d) where d is the number of divisors
- For N ≤ 200,000, this is acceptable

## Implementation Plan

1. Read N and the sequence
2. For each possible period length p (where N % p == 0):
   - Check if sequence[:p] repeated N/p times equals the full sequence
3. If any period works, print "YES", else "NO"
