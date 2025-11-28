#!/bin/bash
# Test if show() leaks tcache metadata after delete()

echo "=== Testing Tcache Leak via show() after delete() ==="
echo "Sequence: Alloc -> Delete (UAF) -> Show (should print tcache fd)"
echo ""

# Create input
cat > /tmp/tcache_leak_input << 'EOF'
1
0
1000
DEADBEEF
2
0
3
0
4
EOF

# Run and capture output
./gemsmith < /tmp/tcache_leak_input 2>&1 | python3 -c "
import sys
data = sys.stdin.buffer.read()

# Find the show() output - it's after the delete success message
parts = data.split(b'sakujo')  # 'deleted' in Japanese
if len(parts) > 1:
    # Everything after 'sakujo' until next menu
    after_delete = parts[1]
    # Look for non-menu text
    lines = after_delete.decode('utf-8', errors='replace').split('\\n')

    print('=== OUTPUT AFTER DELETE (before next menu) ===')
    for line in lines[:20]:  # First 20 lines
        stripped = line.strip()
        if stripped and not any(x in stripped for x in ['［', '］', '｜', '＋', '－', '＞', 'Gemu', 'Ken']):
            print(f'>> {repr(stripped)[:100]}')
            # Check for potential heap leak (non-printable chars)
            if any(ord(c) < 32 or ord(c) > 126 for c in stripped[:50]):
                print('   ^^^ POSSIBLE HEAP LEAK (non-printable chars detected!)')
"

rm -f /tmp/tcache_leak_input
