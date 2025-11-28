#!/usr/bin/env python3
"""
Simple interaction test with Mantra challenge

Author: AI Agent
Purpose: Direct interaction to understand behavior
Created: 2025-11-20
Expected Result: Understand what breaks the binary
Produced Result: TBD
"""

from pwn import *

context.log_level = 'info'

def test_remote():
    p = remote("154.57.164.68", 32556)

    print(p.recv(timeout=2))

    # Weave cord
    p.sendline(b'1')
    print(p.recv(timeout=2))
    p.sendline(b'5')  # 5 beads
    print(p.recv(timeout=2))

    # Tie beads with huge overflow
    p.sendline(b'2')
    print(p.recv(timeout=2))
    p.sendline(b'5')  # tie 5 beads
    print(p.recv(timeout=2))

    # Send progressively longer strings
    for i in range(5):
        payload = b'A' * (8 + i * 100)
        print(f"Sending {len(payload)} bytes...")
        p.sendline(payload)
        resp = p.recv(timeout=2)
        print(f"Response: {resp}")

    p.interactive()

test_remote()
