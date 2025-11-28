#!/bin/bash
# Test what show() reveals after delete() (UAF)

echo "=== Testing show() after delete() (UAF) ==="

# Alloc, Delete, Show
INPUT=$(cat <<'EOF'
1
0
1000
TESTDATA12345
2
0
3
0
4
EOF
)

echo "$INPUT" | timeout 3 ./gemsmith 2>&1 | strings | grep -E "TEST|0x|tcache|free|malloc|heap" -i
