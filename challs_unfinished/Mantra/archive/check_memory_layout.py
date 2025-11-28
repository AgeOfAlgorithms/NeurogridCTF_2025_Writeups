#!/usr/bin/env python3
"""
Check actual memory layout to understand distances

Author: Claude
Purpose: Understand real memory layout distances
Created: 2025-11-23
Expected: See heap and binary locations
Result: TBD
"""

from pwn import *
import time

context.log_level = 'error'

io = process(['./glibc/ld-2.34.so', './mantra'], cwd='/home/sean/ctf/NeurogridCTF_2025/Mantra')
pid = io.pid

print(f"[*] Process PID: {pid}")

# Weave cord
io.sendlineafter(b'>', b'1')
io.sendlineafter(b': ', b'100')

# Give it time to allocate
time.sleep(0.5)

# Read memory map
print(f"\n[*] Memory layout:")
with open(f'/proc/{pid}/maps', 'r') as f:
    lines = f.readlines()
    heap_addr = None
    binary_addr = None

    for line in lines:
        if 'mantra' in line and 'r-xp' in line:  # Code section
            binary_addr = int(line.split('-')[0], 16)
            print(f"Binary (code):  {line.strip()}")
        elif 'mantra' in line:
            print(f"Binary (other): {line.strip()}")
        elif '[heap]' in line:
            heap_addr = int(line.split('-')[0], 16)
            print(f"Heap:           {line.strip()}")

    if heap_addr and binary_addr:
        distance = heap_addr - binary_addr
        units = distance // 8
        print(f"\n[+] Binary base:  0x{binary_addr:x}")
        print(f"[+] Heap base:    0x{heap_addr:x}")
        print(f"[+] Distance:     0x{distance:x} bytes = {distance} bytes")
        print(f"[+] In 8-byte units: {units} units")
        print(f"[+] Negative offset to reach binary from heap: {-units}")

io.close()
