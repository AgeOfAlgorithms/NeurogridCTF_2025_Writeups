#!/bin/bash
# Check memory layout without interaction

# Create simple input
echo -e "3\n0\n" > /tmp/simple_input

# Run with GDB in batch mode
gdb -q gemsmith -batch \
  -ex "set pagination off" \
  -ex "break *main+28" \
  -ex "run < /tmp/simple_input" \
  -ex "printf \"\\n=== MEMORY LAYOUT ===\\n\"" \
  -ex "printf \"Stack (rbp): %p\\n\", \$rbp" \
  -ex "printf \"Stack (rsp): %p\\n\", \$rsp" \
  -ex "info proc mappings" \
  -ex "printf \"\\n=== GLOBAL VARIABLES ===\\n\"" \
  -ex "printf \"buf address: \"" \
  -ex "x/1gx &buf" \
  -ex "printf \"stdin address: \"" \
  -ex "x/1gx &stdin" \
  -ex "printf \"stdout address: \"" \
  -ex "x/1gx &stdout" \
  -ex "quit" 2>&1 | grep -v "pwndbg\|Terminal\|Debuginfod\|_curses"
