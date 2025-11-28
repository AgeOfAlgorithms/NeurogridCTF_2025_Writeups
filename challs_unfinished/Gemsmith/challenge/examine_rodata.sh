#!/bin/bash
# Examine all .rodata strings to find any hidden messages
# Author: Claude Code
# Purpose: Ensure we haven't missed any hidden strings or clues
# Created: 2025-11-23
# Expected: List all strings in .rodata section

echo "=== All strings in .rodata section ==="
objdump -s -j .rodata gemsmith | grep -v "file format\|Contents of section"

echo ""
echo "=== Readable strings from .rodata ==="
strings -a gemsmith | grep -E "HTB|flag|success|upgrade|sword|gem|forge"
