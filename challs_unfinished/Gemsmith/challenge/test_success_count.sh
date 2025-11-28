#!/bin/bash
# Test: Maybe "upgrading" = calling success() via delete() many times?
# "Broken" = operations that call fail()
# "Upgraded" = operations that call success()?

echo "=== Hypothesis: Call success() via delete() for all 14 operations ==="
echo "Pattern: 7x (Alloc + Delete) = 7 success() calls"
echo ""

# 14 operations total: alternating alloc/delete
cat << 'EOF' | timeout 3 ./gemsmith 2>&1 | tail -20
1
0
100
GEM1
2
0
1
0
100
GEM2
2
0
1
0
100
GEM3
2
0
1
0
100
GEM4
2
0
1
0
100
GEM5
2
0
1
0
100
GEM6
2
0
1
0
100
GEM7
2
0
EOF

echo ""
echo "=== Did it upgrade instead of break? ==="
