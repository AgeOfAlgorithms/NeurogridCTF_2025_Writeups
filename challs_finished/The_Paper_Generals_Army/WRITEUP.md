# The Paper General's Army - Writeup

**Challenge**: The Paper General's Army
**Category**: Misc
**Difficulty**: Very Easy
**Points**: 975
**Flag**: `HTB{th3_f0ld3d_l3g10n_r1s3s_1n_th3_m00nl1ght}`

## Challenge Description

The challenge presents a story about a Paper General who could double his army by "folding" under the moonlight. The task is to calculate the size of an army after a certain number of folds, where each fold doubles the count.

## Analysis

This is a coding challenge that requires:
1. Reading T test cases
2. For each test case, reading N (initial soldiers) and K (number of folds)
3. Calculating the final count: N × 2^K
4. Handling up to 500,000 test cases efficiently

### Key Observations

- **Mathematical Formula**: Each fold doubles the count, so after K folds: `N × 2^K`
- **Performance Requirement**: With up to 500,000 test cases, the solution must be optimized for speed
- **Constraints**:
  - 1 ≤ T ≤ 500,000
  - 1 ≤ N ≤ 100
  - 1 ≤ K ≤ 50

## Solution Approach

### Initial Attempt

The first solution used a straightforward approach:
```python
T = int(input())
for _ in range(T):
    N, K = map(int, input().split())
    result = N * (2 ** K)
    print(result)
```

**Problem**: This failed on test case 10 with "Time limit exceeded" due to slow I/O and repeated power calculations.

### Optimized Solution

The optimized solution addresses performance issues:

1. **Bulk I/O**: Read all input at once using `sys.stdin.read()` instead of repeated `input()` calls
2. **Bit Shifting**: Use `N << K` instead of `N * (2 ** K)` for faster computation
3. **Batch Output**: Collect results and print all at once instead of line-by-line

```python
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
    N = int(input_data[idx])
    K = int(input_data[idx + 1])
    idx += 2

    # Using bit shifting: N << K is equivalent to N * 2^K
    result = N << K
    results.append(str(result))

# Output all results at once
print('\n'.join(results))
```

## Key Optimizations

1. **Bit Shifting (`N << K`)**: This operation is much faster than exponentiation (`2 ** K`) because it's a simple binary shift operation
2. **Bulk Input Reading**: Using `sys.stdin.read()` reads all input at once, avoiding multiple system calls
3. **Batch Output**: Building a list of results and printing once reduces I/O overhead

## Exploitation Steps

1. Accessed the challenge at `http://154.57.164.65:32754/`
2. Analyzed the problem requirements
3. Developed and tested the solution locally
4. Submitted the optimized solution via the web interface
5. Received the flag: `HTB{th3_f0ld3d_l3g10n_r1s3s_1n_th3_m00nl1ght}`

## Lessons Learned

- Performance optimization is crucial for competitive programming challenges with large input sizes
- Bit shifting is an efficient alternative to power calculations when working with powers of 2
- Bulk I/O operations significantly improve performance compared to line-by-line processing
- Even "Very Easy" challenges can require optimization to pass all test cases

## Flag

`HTB{th3_f0ld3d_l3g10n_r1s3s_1n_th3_m00nl1ght}`
