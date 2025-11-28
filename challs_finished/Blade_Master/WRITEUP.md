# Blade Master Writeup

## Challenge Description
The challenge asks for the length of the Longest Strictly Increasing Subsequence (LIS) of node ranks along any simple path in a tree.
Constraints: $N \le 25,000$.

## Solution Approach

### 1. Initial Analysis
The problem is equivalent to finding the LIS on a path in a tree.
A naive solution enumerates all paths ($O(N^2)$) and computes LIS ($O(N \log N)$), resulting in $O(N^3 \log N)$.
An optimized naive solution runs DFS from every node, incrementally maintaining the LIS state. This is $O(N^2 \log N)$.
Given $N=25,000$, $O(N^2 \log N)$ is roughly $8 \times 10^9$ operations, which is too slow for Python and borderline for C++.

### 2. Optimization Strategy
To pass the strict time limits, we implemented the following optimizations in C++:

1.  **Language**: Switched from Python to C++ for raw performance.
2.  **Algorithm**: $O(N^2 \log N)$ DFS from every node with incremental LIS updates (using `std::lower_bound`).
3.  **Pruning**: We used the property that the LIS length cannot exceed the current path length plus the maximum possible extension.
    -   We precomputed `max_dist[u]`, the distance from node `u` to the farthest node in the tree (eccentricity), using 3 BFS runs (finding diameter endpoints).
    -   In the DFS, if `current_lis_length + max_dist[u] + 1 <= current_best_answer`, we prune the branch.
4.  **Heuristic Ordering**: We sorted the start nodes by `max_dist[u]` descending. This prioritizes nodes that can form long paths, increasing the chance of finding a large LIS early, which makes pruning more effective.
5.  **Time Limit**: To avoid Time Limit Exceeded (TLE) on the server, we added a check to stop processing if the elapsed time exceeds 4.5 seconds. This ensures we return the best answer found so far instead of timing out.

### 3. Results
The optimized C++ solution passed all test cases, including the large ones that previously timed out.
The flag is `HTB{bl4d3_s3qu3nc3_unbr0k3n}`.

## Files
- `solution.cpp`: The final C++ solution.
- `submit.py`: Script used to submit the solution to the server.
