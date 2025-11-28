#!/usr/bin/env python3
"""
Author: Claude (AI Agent)
Purpose: Solve the Fivefold Door challenge - Longest Increasing Subsequence
Created: 2025-11-20
Updated: 2025-11-20

Algorithm: Binary Search + DP for O(n log n) time complexity
Expected Result: Length of longest strictly increasing subsequence
Produced Result: Successfully solved - Flag: HTB{LIS_0f_th3_f1v3}
"""

from bisect import bisect_left

def longest_increasing_subsequence(arr):
    """
    Find the length of the longest strictly increasing subsequence.

    Time Complexity: O(n log n)
    Space Complexity: O(n)

    Args:
        arr: List of integers representing sigil strengths

    Returns:
        Length of the longest strictly increasing subsequence
    """
    if not arr:
        return 0

    # dp[i] will store the smallest tail element of all
    # increasing subsequences of length i+1
    dp = []

    for num in arr:
        # Find the position where num should be inserted
        # to maintain sorted order
        pos = bisect_left(dp, num)

        # If num is larger than all elements in dp, append it
        if pos == len(dp):
            dp.append(num)
        else:
            # Replace the first element >= num
            dp[pos] = num

    return len(dp)

def main():
    # Read input
    n = int(input())
    arr = list(map(int, input().split()))

    # Calculate and print result
    result = longest_increasing_subsequence(arr)
    print(result)

if __name__ == "__main__":
    main()
