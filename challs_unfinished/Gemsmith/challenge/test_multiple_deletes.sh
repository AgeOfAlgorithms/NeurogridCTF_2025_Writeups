#!/bin/bash
# Test calling delete() multiple times
# Hypothesis: Maybe multiple success() calls = "upgrading"?

echo "=== Testing multiple delete() calls (multiple success() triggers) ==="

# Pattern: Alloc, Delete, Alloc, Delete, ...
# This calls success() many times
INPUT=$(cat <<'EOF'
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
)

echo "$INPUT" | timeout 5 ./gemsmith 2>&1 | grep -E "sakujo|HTB|flag|upgrade|success|broken|koware" -i | tail -20
