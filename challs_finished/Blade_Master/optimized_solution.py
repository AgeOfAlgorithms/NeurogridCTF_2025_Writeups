#!/usr/bin/env python3
"""
Blade Master - Optimized Solution
Author: AI Agent
Purpose: Find longest increasing subsequence along any tree path
Created: 2025-11-20
Updated: 2025-11-20

Optimization: Maintain LIS incrementally during DFS instead of recomputing
Time Complexity: O(N² log N) instead of O(N³ log N)

Expected Result: Pass all test cases including larger ones
Produced Result: TBD
"""

from bisect import bisect_left

n = int(input())
ranks = [0] + list(map(int, input().split()))
adj = [[] for _ in range(n + 1)]
for _ in range(n - 1):
    u, v = map(int, input().split())
    adj[u].append(v)
    adj[v].append(u)

ans = 1

def dfs(node, parent, lis_tails):
    """
    DFS that maintains LIS incrementally.
    lis_tails: array where lis_tails[i] is the smallest ending value
               of all increasing subsequences of length i+1
    """
    global ans
    ans = max(ans, len(lis_tails))

    for child in adj[node]:
        if child != parent:
            # Add ranks[child] to LIS and track what changed
            pos = bisect_left(lis_tails, ranks[child])

            # Save old value if we're replacing
            old_val = None
            old_len = len(lis_tails)

            if pos == len(lis_tails):
                lis_tails.append(ranks[child])
            else:
                old_val = lis_tails[pos]
                lis_tails[pos] = ranks[child]

            # Recurse
            dfs(child, node, lis_tails)

            # Undo the change
            if pos == old_len:
                lis_tails.pop()
            else:
                lis_tails[pos] = old_val

# Start DFS from each node
for start in range(1, n + 1):
    dfs(start, -1, [ranks[start]])

print(ans)
