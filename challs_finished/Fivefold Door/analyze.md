# Fivefold Door - Analysis

## Challenge Type
Longest Increasing Subsequence (LIS) Problem

## Problem Statement
Given a sequence of N integers representing sigil strengths, find the length of the longest strictly increasing subsequence.

## Input Format
```
Line 1: N (number of sigils)
Line 2: N space-separated integers
```

## Output Format
```
Single integer: length of longest strictly increasing subsequence
```

## Constraints
- 2 ≤ N ≤ 10^6
- 0 ≤ aᵢ ≤ 10^9

## Example
**Input:**
```
8
3 10 2 1 20 4 6 9
```

**Output:**
```
4
```

**Explanation:**
One possible longest increasing subsequence: 3 → 4 → 6 → 9 (length 4)

## Algorithm Analysis

### Approach: Binary Search + Dynamic Programming (O(n log n))

Since N can be up to 10^6, we need an efficient O(n log n) solution instead of O(n²).

**Algorithm:**
1. Maintain an array `dp` where `dp[i]` stores the smallest tail element of all increasing subsequences of length `i+1`
2. For each element in the sequence:
   - Use binary search to find the position where it should be placed in `dp`
   - If the element is larger than all elements in `dp`, append it
   - Otherwise, replace the first element in `dp` that is >= the current element
3. The length of `dp` at the end is the answer

**Time Complexity:** O(n log n)
**Space Complexity:** O(n)

## Solution Strategy

1. Read N and the sequence
2. Use binary search (bisect_left) to efficiently build the LIS
3. Return the length of the resulting array
