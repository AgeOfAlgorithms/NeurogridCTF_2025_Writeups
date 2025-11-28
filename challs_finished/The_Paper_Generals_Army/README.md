# The Paper General's Army

## Challenge Information
- **Challenge Name**: The Paper General's Army
- **Category**: Misc
- **Difficulty**: Very Easy
- **Points**: 975
- **Status**: ✅ SOLVED
- **Start Time**: 2025-11-20 14:04:00
- **Solve Time**: 2025-11-20 14:09:00

## Description
When the moon was high and the world was quiet, the Paper General would whisper a single word: "Fold."
Under that silver glow, each soldier of parchment would split like a reflection in still water, doubling the ranks without a sound.
Only a trace of that forgotten ritual remains — the secret mathematics behind a growing legion.
Tonight, beneath the same moon, you are given the chance to summon the Folded Army yourself.

## Challenge Details
- **Docker Instance**: Web application
- **Challenge ID**: 63439
- **Flag ID**: 783694
- **Download Files**: None provided

## Solution
This is a coding challenge requiring calculation of N × 2^K for multiple test cases. The key was optimizing for performance with up to 500,000 test cases by using:
1. Bit shifting (N << K) instead of exponentiation
2. Bulk I/O operations
3. Batch output

## Flag
`HTB{th3_f0ld3d_l3g10n_r1s3s_1n_th3_m00nl1ght}`

## Files
- [solution.py](solution.py) - Optimized Python solution
- [WRITEUP.md](WRITEUP.md) - Detailed writeup
