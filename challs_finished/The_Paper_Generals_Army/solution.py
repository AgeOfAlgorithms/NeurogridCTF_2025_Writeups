#!/usr/bin/env python3
"""
Author: Claude (AI Agent)
Purpose: Optimized solution for "The Paper General's Army" challenge
Assumptions: Each fold doubles the number of soldiers
Expected result: Flag from the challenge
Date: 2025-11-20 (Updated)
Optimization: Using bit shifting instead of power calculation
"""

import sys

# Read all input at once for faster I/O
input_data = sys.stdin.read().strip().split()
idx = 0

# Read number of test cases
T = int(input_data[idx])
idx += 1

# Process each test case
results = []
for _ in range(T):
    # Read N (initial soldiers) and K (number of folds)
    N = int(input_data[idx])
    K = int(input_data[idx + 1])
    idx += 2

    # Each fold doubles the count, so after K folds: N * 2^K
    # Using bit shifting for better performance: N << K is equivalent to N * 2^K
    result = N << K

    # Store result
    results.append(str(result))

# Output all results at once
print('\n'.join(results))
