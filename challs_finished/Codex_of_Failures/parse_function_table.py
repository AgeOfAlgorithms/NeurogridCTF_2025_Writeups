#!/usr/bin/env python3
# Parse function pointer table to get the order of errno functions
# Author: Claude
# Purpose: Extract the 28-function sequence from the binary
# Created: 2025-11-22
# Last run: Not yet executed

import struct

# Hexdump from Ghidra at address 0014cc80
hexdata = """
aa 34 10 00 00 00 00 00  cc 3c 10 00 00 00 00 00
86 38 10 00 00 00 00 00  93 34 10 00 00 00 00 00
aa 34 10 00 00 00 00 00  d0 34 10 00 00 00 00 00
ec 34 10 00 00 00 00 00  9d 3a 10 00 00 00 00 00
86 38 10 00 00 00 00 00  e8 36 10 00 00 00 00 00
ea 3b 10 00 00 00 00 00  82 3c 10 00 00 00 00 00
aa 34 10 00 00 00 00 00  ec 34 10 00 00 00 00 00
9d 3a 10 00 00 00 00 00  86 38 10 00 00 00 00 00
cc 3c 10 00 00 00 00 00  82 3c 10 00 00 00 00 00
ea 3b 10 00 00 00 00 00  e8 36 10 00 00 00 00 00
86 38 10 00 00 00 00 00  9d 3a 10 00 00 00 00 00
ec 34 10 00 00 00 00 00  d0 34 10 00 00 00 00 00
aa 34 10 00 00 00 00 00  93 34 10 00 00 00 00 00
ec 34 10 00 00 00 00 00  d0 34 10 00 00 00 00 00
"""

# Parse hex bytes
bytes_data = bytes.fromhex(hexdata.replace('\n', '').replace(' ', ''))

# Extract function pointers (8 bytes each, little endian)
function_ptrs = []
for i in range(0, len(bytes_data), 8):
    ptr = struct.unpack('<Q', bytes_data[i:i+8])[0]
    function_ptrs.append(ptr)

# Map addresses to function names and errno values
function_map = {
    0x00103493: ("setuid(0)", "EPERM", 1),
    0x001034aa: ("open(flag_file)", "ENOENT", 2),
    0x001034d0: ("kill(-0x21524111, 0x1a4)", "ESRCH", 3),
    0x001034ec: ("setitimer+pause", "EINTR", 4),
    0x001036e8: ("lseek+read(/proc/self/mem)", "EIO", 5),
    0x00103886: ("open(socket)", "ENXIO", 6),
    0x00103a9d: ("execve(/bin/true)", "?", 0),  # Unknown, need to test
    0x00103bea: ("execve(exe_file)", "?", 0),  # Unknown, need to test
    0x00103c82: ("read(-1)", "EBADF", 9),
    0x00103ccc: ("waitpid(-1)", "ECHILD", 10),
}

print("Function call sequence (28 functions):\n")
for idx, ptr in enumerate(function_ptrs):
    if ptr in function_map:
        name, errno_name, errno_val = function_map[ptr]
        print(f"[{idx:2d}] 0x{ptr:08x} → {name:30s} errno={errno_name} ({errno_val})")
    else:
        print(f"[{idx:2d}] 0x{ptr:08x} → UNKNOWN")

print(f"\nTotal: {len(function_ptrs)} functions")
print("\nFunction index mapping for C program:")
for idx, ptr in enumerate(function_ptrs):
    if ptr in function_map:
        print(f"    errnos[{idx}] = {function_map[ptr][0]};")
