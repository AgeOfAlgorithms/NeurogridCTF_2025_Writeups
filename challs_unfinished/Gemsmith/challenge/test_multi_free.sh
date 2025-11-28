#!/bin/bash
# Test with multiple frees to get non-NULL tcache pointers

echo "=== Testing tcache with multiple freed chunks ==="
echo "Alloc A, Alloc B, Free B, Free A, Show A"
echo "This should make A->next point to B (non-NULL heap address)"
echo ""

# Create two chunks, free them in reverse order
# Then show the first one (should contain pointer to second)
cat << 'EOF' | timeout 2 ./gemsmith 2>&1 | tee /tmp/multi_free.txt
1
0
100
AAAA
1
0
100
BBBB
2
0
2
0
3
0
4
EOF

echo ""
echo "=== Checking for leaked addresses ==="
cat /tmp/multi_free.txt | strings | grep -v "Gemu\|Ken\|Indekku\|Shuu\|hyou\|sakujo\|tsuika" | tail -10

rm -f /tmp/multi_free.txt
