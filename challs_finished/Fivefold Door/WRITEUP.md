# Fivefold Door - Writeup

**Challenge:** Fivefold Door
**Category:** Algorithm/Programming
**Difficulty:** Medium
**Points:** 950
**Flag:** `HTB{LIS_0f_th3_f1v3}`

## Challenge Description

The challenge presented a web interface with a coding problem: finding the longest strictly increasing subsequence (LIS) from a given sequence of integers representing "sigil strengths" on an ancient door.

## Vulnerability/Algorithm Analysis

This is a classic **Longest Increasing Subsequence (LIS)** problem in computer science.

### Key Observations:
1. The problem requires finding the **longest** strictly increasing subsequence
2. The constraint N ≤ 10^6 means we need an efficient algorithm
3. A naive O(n²) dynamic programming solution would be too slow
4. An O(n log n) solution using binary search is optimal

### Algorithm Approach:

The efficient solution uses **binary search with dynamic programming**:

1. Maintain an array `dp` where `dp[i]` stores the smallest tail element of all increasing subsequences of length `i+1`
2. For each element in the input sequence:
   - Use binary search (`bisect_left`) to find the position where it should be placed
   - If the element is larger than all elements in `dp`, append it
   - Otherwise, replace the first element in `dp` that is ≥ the current element
3. The final length of `dp` is the answer

**Why this works:**
- We maintain the invariant that `dp` is always sorted
- By storing the smallest possible tail for each length, we maximize the chance of extending subsequences
- Binary search gives us O(log n) per element, resulting in O(n log n) total complexity

## Exploitation Steps

1. **Identified the problem type:** Recognized this as a standard LIS problem from the description

2. **Analyzed constraints:** With N up to 10^6, needed an efficient O(n log n) algorithm

3. **Implemented the solution:**
   ```python
   from bisect import bisect_left

   def longest_increasing_subsequence(arr):
       dp = []
       for num in arr:
           pos = bisect_left(dp, num)
           if pos == len(dp):
               dp.append(num)
           else:
               dp[pos] = num
       return len(dp)
   ```

4. **Tested locally:** Verified with the provided example (input: `[3, 10, 2, 1, 20, 4, 6, 9]`, expected output: `4`)

5. **Submitted to server:** Posted the solution code to the challenge endpoint at `/run`

6. **Retrieved flag:** Server validated the solution against all test cases and returned the flag

## Example Walkthrough

For input `[3, 10, 2, 1, 20, 4, 6, 9]`:

| Element | dp array | Explanation |
|---------|----------|-------------|
| 3 | [3] | Start with first element |
| 10 | [3, 10] | 10 > 3, append |
| 2 | [2, 10] | Replace 3 with 2 (smaller tail for length 1) |
| 1 | [1, 10] | Replace 2 with 1 (even smaller tail) |
| 20 | [1, 10, 20] | 20 > 10, append |
| 4 | [1, 4, 20] | Replace 10 with 4 |
| 6 | [1, 4, 6] | Replace 20 with 6 |
| 9 | [1, 4, 6, 9] | 9 > 6, append |

Final answer: `len(dp) = 4`

One possible LIS: `1 → 4 → 6 → 9` or `3 → 4 → 6 → 9`

## Tools Used

- Python 3 with `bisect` module for binary search
- `requests` library for HTTP communication
- HTB MCP tools for flag submission

## Flag

`HTB{LIS_0f_th3_f1v3}`

## Key Takeaways

1. Recognize classic algorithmic problems and their optimal solutions
2. Consider time complexity constraints when choosing algorithms
3. Binary search can optimize many dynamic programming problems
4. The "patience sorting" technique (what this algorithm is based on) is elegant and efficient
