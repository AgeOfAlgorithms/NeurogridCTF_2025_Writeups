# Blade Master - Final Attempt Documentation

## Challenge Information
- **Category**: Algorithm/Programming
- **Difficulty**: Hard
- **Points**: 975
- **Solves**: 6

## Problem Summary
Find the longest strictly increasing subsequence of node ranks along any simple path (no repeated edges) in a tree.

## Solutions Developed

### 1. working_solution_slow.py (Original - BEST RESULT)
- **Approach**: Brute force - enumerate all tree paths from each starting node, compute LIS for each path
- **Time Complexity**: O(N² × N log N) = O(N³ log N)
- **Result**: **Passed 7 tests, timed out on test 8**
- **Status**: Correct algorithm, but too slow for larger inputs

### 2. optimized_solution.py (Incremental LIS Maintenance)
- **Approach**: Maintain LIS tails array incrementally during DFS, avoiding full recomputation
- **Time Complexity**: O(N² log N)
- **Result**: **Wrong answer on test 7**
- **Status**: Contains a subtle bug that only appears in certain edge cases

### 3. Test Results Comparison
| Solution | Test 1 | Test 2 | Test 3 | Server Test 7 | Server Test 8 |
|----------|--------|--------|--------|---------------|---------------|
| Slow     | ✅ (4)  | ✅ (3)  | ✅ (4)  | ✅ Pass       | ❌ Timeout    |
| Optimized| ✅ (4)  | ✅ (3)  | ✅ (4)  | ❌ Wrong Ans  | N/A           |

## Key Findings

###  The Incremental LIS Bug
The optimized solution produces correct results on all local test cases (test1, test2, test3) but fails on the server's test case 7. This indicates there's an edge case not covered by the local tests. The bug likely involves:
- Specific tree structures or rank distributions
- Edge cases in the backtracking logic when restoring LIS state
- Possible issues with duplicate ranks in certain configurations

### Algorithmic Challenges
This problem requires O(N²) or better complexity to pass all tests with N ≤ 25000. Possible approaches:
1. **Tree DP with Rerooting**: Track sequences ending at each value, combine across subtrees
2. **Advanced Memoization**: Cache partial results to avoid redundant computation
3. **Different Problem Formulation**: Reformulate as a DP problem on tree paths

## Why This Challenge Is Unsolved

1. **Complexity Barrier**: The correct O(N³ log N) solution is too slow
2. **Optimization Bug**: The O(N² log N) optimization has a subtle bug in edge cases
3. **Time Constraints**: Insufficient time to implement proper tree DP with rerooting
4. **Limited Debugging**: Can't see actual test case 7 to debug the issue

## Lessons Learned

1. **Incremental maintenance** of complex data structures (like LIS) during backtracking DFS requires extreme care
2. **Local tests** may not cover all edge cases - need comprehensive test generation
3. **Tree DP problems** at this difficulty often require specialized techniques beyond standard DFS
4. **Trade-off**: Sometimes a slow correct solution is better than a fast buggy one

## Best Submission
**working_solution_slow.py** - Passes 7 tests before timeout, which is the best verified result.

## Recommendations for Future Attempts
1. Implement proper tree rerooting DP
2. Study similar problems (e.g., "longest path in tree with constraints")
3. Generate more comprehensive test cases
4. Consider if there's a mathematical insight that simplifies the problem
5. Look for O(N²) DP formulation that tracks (node, ending_value) states
