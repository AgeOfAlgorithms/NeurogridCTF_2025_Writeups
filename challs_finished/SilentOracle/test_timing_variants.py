#!/usr/bin/env python3
"""Test if 'i's in 'Timing' are letter 'i' or digit '1'"""

import socket
import time

HOST = "154.57.164.71"
PORT = 30989

def test_string(guess):
    try:
        start = time.time()
        sock = socket.socket()
        sock.settimeout(30)
        sock.connect((HOST, PORT))

        data = b''
        sock.settimeout(5)
        try:
            while b'ATTEMPT YOUR SCHEMES:' not in data:
                data += sock.recv(4096)
        except: pass

        sock.sendall((guess + '\n').encode())

        response = b''
        sock.settimeout(15)
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk: break
                response += chunk
                if b'BANISHED' in response or b'ADVENTURE' in response: break
        except: pass

        sock.close()
        elapsed = time.time() - start
        is_success = b'CONTINUE ON WITH YOUR ADVENTURE' in response
        return elapsed, is_success
    except Exception as e:
        return None, False

print("="*70)
print("Testing 'Timing' variants - which 'i's are digit '1'?")
print("="*70)

# Test all combinations
variants = [
    ("HTB{Timing_zz", "Both i's are letter 'i'"),
    ("HTB{T1ming_zz", "First i is digit '1'"),
    ("HTB{Tim1ng_zz", "Second i is digit '1'"),
    ("HTB{T1m1ng_zz", "Both i's are digit '1'"),
]

for guess, desc in variants:
    print(f"\n{desc}")
    print(f"Testing: '{guess}'")
    elapsed, success = test_string(guess)

    if success:
        print(f"  → {elapsed:.2f}s ✓✓✓ COMPLETE FLAG FOUND!")
        print(f"\nFLAG: {guess}")
        break
    elif elapsed:
        if elapsed < 2.0:
            print(f"  → {elapsed:.2f}s ← FAST! This is CORRECT")
        else:
            print(f"  → {elapsed:.2f}s (wrong variant)")

    time.sleep(10)

print("\n" + "="*70)
