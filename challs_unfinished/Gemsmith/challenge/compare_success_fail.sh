#!/bin/bash
# Compare success() and fail() at assembly level
# Author: Claude Code
# Purpose: Find any exploitable differences between the two functions
# Created: 2025-11-23
# Expected: Should show they're nearly identical except for the string parameter

echo "=== Disassembly of success() ==="
objdump -d gemsmith | awk '/^[0-9a-f]+ <success>:/,/^$/ {print}'

echo ""
echo "=== Disassembly of fail() ==="
objdump -d gemsmith | awk '/^[0-9a-f]+ <fail>:/,/^$/ {print}'

echo ""
echo "=== Checking if success() is ever called ==="
objdump -d gemsmith | grep "call.*<success>"

echo ""
echo "=== All calls to fail() ==="
objdump -d gemsmith | grep "call.*<fail>"
