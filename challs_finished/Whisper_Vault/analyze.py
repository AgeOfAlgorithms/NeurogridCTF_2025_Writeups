#!/usr/bin/env python3
"""
Author: AI Agent
Purpose: Analyze whisper_vault binary and find ROP gadgets
Created: 2025-11-20
Updated: 2025-11-20
Expected Result: Find useful ROP gadgets for exploitation
Produced Result: TBD
"""

from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

# Load the binary
elf = ELF('./whisper_vault')

# Create ROP object
rop = ROP(elf)

# Find useful gadgets
print("\n[*] Searching for useful gadgets...")

# Try to find pop rdi
try:
    pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
    print(f"[+] pop rdi; ret = {hex(pop_rdi)}")
except:
    print("[-] pop rdi; ret not found")

# Try to find pop rsi
try:
    pop_rsi = rop.find_gadget(['pop rsi', 'ret'])[0]
    print(f"[+] pop rsi; ret = {hex(pop_rsi)}")
except:
    print("[-] pop rsi; ret not found")

# Try to find pop rdx
try:
    pop_rdx = rop.find_gadget(['pop rdx', 'ret'])[0]
    print(f"[+] pop rdx; ret = {hex(pop_rdx)}")
except:
    print("[-] pop rdx; ret not found")

# Try to find pop rax
try:
    pop_rax = rop.find_gadget(['pop rax', 'ret'])[0]
    print(f"[+] pop rax; ret = {hex(pop_rax)}")
except:
    print("[-] pop rax; ret not found")

# Find syscall
try:
    syscall = rop.find_gadget(['syscall'])[0]
    print(f"[+] syscall = {hex(syscall)}")
except:
    print("[-] syscall not found")

# Check for strings
print("\n[*] Searching for useful strings...")
flag_txt = next(elf.search(b'flag.txt'), None)
if flag_txt:
    print(f"[+] 'flag.txt' found at {hex(flag_txt)}")
else:
    print("[-] 'flag.txt' not found")

bin_sh = next(elf.search(b'/bin/sh'), None)
if bin_sh:
    print(f"[+] '/bin/sh' found at {hex(bin_sh)}")
else:
    print("[-] '/bin/sh' not found")

# Print some ROP info
print("\n[*] Available ROP gadgets (first 20):")
for i, gadget in enumerate(rop.gadgets.items()):
    if i >= 20:
        break
    addr, insns = gadget
    print(f"  {hex(addr)}: {'; '.join(insns)}")

print("\n[*] ELF Info:")
print(f"  Arch: {elf.arch}")
print(f"  Bits: {elf.bits}")
print(f"  Entry: {hex(elf.entry)}")
print(f"  PIE: {elf.pie}")
print(f"  NX: {elf.nx}")
print(f"  Canary: {elf.canary}")
