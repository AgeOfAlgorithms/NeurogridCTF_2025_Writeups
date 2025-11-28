# Blade Master

**Category**: Algorithm/Programming (Category ID: 11)
**Difficulty**: Hard
**Points**: 975
**Solves**: 6
**Status**: ✅ **Solved**
**Flag**: `HTB{bl4d3_s3qu3nc3_unbr0k3n}`

## Description
In the age of still swords, the clans forged their loyalty into iron.
Each shrine holds a single blade — humble, ranked, waiting.
The disciple's pilgrimage is simple: begin anywhere, end anywhere, but never tread the same road twice.
Collect the blades in a rising harmony of power, or watch the road seal behind you forever.

## Challenge Type
- Web interface with code submission
- No downloadable files

## Problem
Find the longest strictly increasing subsequence of node ranks along any simple path (no repeated edges) in a tree.

**Constraints**:
- 5 ≤ N ≤ 25,000 (number of shrines/nodes)
- 1 ≤ Ri ≤ 25,000 (blade ranks)
- Tree structure (N-1 edges, connected, no cycles)

## Solution Summary

### Best Result: working_solution_slow.py
- **Approach**: Brute force enumeration of all paths with LIS computation
- **Time Complexity**: O(N³ log N)
- **Result**: Passed 7 tests, timed out on test 8
- **Status**: Correct but too slow for all test cases

### Failed Optimization: optimized_solution.py
- **Approach**: Incremental LIS maintenance during DFS
- **Time Complexity**: O(N² log N)
- **Result**: Wrong answer on test 7
- **Status**: Contains edge case bug

## Files
- [solution.cpp](solution.cpp) - **Final Solved Solution** (C++ with pruning & time limit)
- [submit.py](submit.py) - Submission script
- [WRITEUP.md](WRITEUP.md) - Solution explanation
- [PREVIOUS_ATTEMPT.md](PREVIOUS_ATTEMPT.md) - Analysis of previous failed attempts
- [working_solution_slow.py](working_solution_slow.py) - Python brute force (correct but slow)
- [optimized_solution.py](optimized_solution.py) - Python optimized (buggy/slow)
- Test cases: test1.txt, test2.txt, test3.txt

## Why Unsolved
1. The correct O(N³ log N) solution is too slow for larger inputs
2. The O(N² log N) optimization has a subtle bug in certain edge cases
3. Requires advanced tree DP with rerooting for optimal solution
4. Limited time to implement and debug complex DP approach

See [FINAL_ATTEMPT.md](FINAL_ATTEMPT.md) for complete analysis and lessons learned.
