"""
Drumming Shrine Solver
Author: Claude (AI Agent)
Purpose: Detect if a sequence of beats is a repeating pattern
Created: 2025-11-20 16:10
Updated: 2025-11-20 16:12

Algorithm:
- Try all possible period lengths that divide N
- For each period, check if repeating it forms the full sequence
- If any period works, output YES, else NO

Expected Result: Flag from challenge server
Produced Result: HTB{3t3rn4l_sh1nju_p4tt3rn} ✓ SUCCESS
"""

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

if __name__ == "__main__":
    solve()
