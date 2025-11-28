# Drumming Shrine - Writeup

**Challenge:** Drumming Shrine
**Category:** ML/AI
**Difficulty:** Easy
**Points:** 925
**Solves:** 11
**Flag:** `HTB{3t3rn4l_sh1nju_p4tt3rn}`

## Challenge Description

At dusk, Mount Tsukimori breathes. The old shrine's drums answer with a pulse that never quite fades—steady, familiar, unsettling. Is it the wind finding the same grooves in cracked wood, or a spirit caught in a loop, replaying a perfect rhythm it refuses to forget? Listen closely. If the mountain is repeating itself, you'll hear the seam.

## Initial Analysis

The challenge presented a web-based coding interface with the following problem:

**Problem:** Given a sequence of N drum beats (integers), determine if the entire sequence can be formed by repeating a smaller prefix pattern.

**Input Format:**
- Line 1: Integer N (length of sequence)
- Line 2: N space-separated integers

**Output:**
- "YES" if the sequence is a repeating pattern
- "NO" otherwise

**Examples:**
- `[2, 1, 2, 1, 2, 1]` → YES (pattern `[2, 1]` repeats 3 times)
- `[4, 2, 4, 2, 3, 4, 1, 6, 10 7]` → NO (no repeating pattern)

## Vulnerability Analysis

This wasn't a traditional security vulnerability but rather an algorithmic challenge. The "vulnerability" was understanding the mathematical property of periodic sequences.

## Approach

The solution involves checking all possible period lengths that divide N:

1. **Iterate through potential period lengths:** For each divisor of N
2. **Extract the pattern:** Take the first `period_len` elements
3. **Verify repetition:** Check if repeating this pattern reconstructs the entire sequence
4. **Return result:** If any valid period < N is found, return "YES", else "NO"

## Solution

```python
def solve():
    # Read input
    n = int(input())
    beats = list(map(int, input().split()))

    # Try all possible period lengths (divisors of n)
    for period_len in range(1, n + 1):
        # Period length must divide n evenly
        if n % period_len != 0:
            continue

        # Extract the potential pattern
        pattern = beats[:period_len]

        # Check if repeating this pattern gives us the full sequence
        is_repeating = True
        for i in range(n):
            if beats[i] != pattern[i % period_len]:
                is_repeating = False
                break

        if is_repeating and period_len < n:
            # Found a repeating pattern (must be smaller than full length)
            print("YES")
            return

    # No repeating pattern found
    print("NO")
```

## Exploitation Steps

1. **Access the challenge:** Started the Docker container and accessed the web interface
2. **Understand the problem:** Analyzed the examples and identified it as a pattern detection problem
3. **Develop solution:** Implemented a brute-force algorithm to check all possible periods
4. **Test locally:** Verified the solution against provided examples
5. **Submit to server:** POSTed the code to `/run` endpoint
6. **Retrieve flag:** Server returned: `HTB{3t3rn4l_sh1nju_p4tt3rn}`

## Key Insights

- The challenge title "Drumming Shrine" and description about "repeating rhythm" were strong hints about pattern repetition
- The flag `3t3rn4l_sh1nju_p4tt3rn` references eternal patterns, confirming the theme
- This is a classic algorithmic problem that can be solved with:
  - KMP failure function (O(N) time)
  - Brute force divisor checking (O(N * d) time)
  - String concatenation trick (O(N²) time)

## Complexity Analysis

- **Time Complexity:** O(N * d) where d is the number of divisors of N
- **Space Complexity:** O(N) for storing the input sequence

For N ≤ 200,000, this approach is efficient enough.

## Timeline

- **Start:** 2025-11-20 16:06
- **Analysis Complete:** 2025-11-20 16:10
- **Solution Developed:** 2025-11-20 16:11
- **Flag Retrieved:** 2025-11-20 16:12
- **Total Time:** ~6 minutes

## Lessons Learned

1. Pattern recognition problems often involve checking divisors
2. Clear problem examples help verify solution correctness before submission
3. The ML/AI category can include algorithmic challenges, not just machine learning
