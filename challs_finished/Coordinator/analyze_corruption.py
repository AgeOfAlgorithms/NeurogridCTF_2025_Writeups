#!/usr/bin/env python3
"""
Analyze where corruption starts and try to infer the flag
"""
import json
import requests
import random
from decimal import Decimal, getcontext
from fpylll import IntegerMatrix, LLL
from z3 import *

getcontext().prec = 150

HOST = "154.57.164.81"
PORT = 32397
BASE_URL = f"http://{HOST}:{PORT}"

def load_samples():
    with open('samples_fresh.json', 'r') as f:
        return json.load(f)

def recover_coeffs_lll(lat, lon, south):
    lon_len = len(str(lon))
    lon_dec = Decimal(lon)
    lat_dec = Decimal(lat)

    for k in range(12):
        scale = Decimal(10) ** (lon_len + k)
        val_abs = lat_dec + (lon_dec / scale)
        x_val = -val_abs if south == 1 else val_abs

        K = 10**120
        X = int(x_val * K)
        X2 = int(x_val * x_val * K)

        M = IntegerMatrix(3, 3)
        M[0, 0], M[0, 2] = 1, X2
        M[1, 1], M[1, 2] = 1, X
        M[2, 2] = K

        LLL.reduction(M)

        for i in range(M.nrows):
            a, b = int(M[i][0]), int(M[i][1])
            c = int(round(-(a * x_val * x_val + b * x_val)))
            ta, tb, tc = (-a, -b, -c) if a > 0 else (a, b, c)
            if -(2**32) <= ta <= 0 and 0 <= tb < 2**32 and 0 <= tc < 2**32:
                return ta, tb, tc
    return None

def temper(y):
    y = y ^ LShR(y, 11)
    y = y ^ ((y << 7) & 0x9d2c5680)
    y = y ^ ((y << 15) & 0xefc60000)
    y = y ^ LShR(y, 18)
    return y

def untemper(y):
    s, v = Solver(), BitVec('v', 32)
    s.add(temper(v) == y)
    s.check()
    return s.model()[v].as_long()

samples = load_samples()
outputs = [val for s in samples[:210] if (r := recover_coeffs_lll(s['lat'], s['lon'], s['south'])) for val in [-r[0], r[1], r[2]]]
state = [untemper(y) for y in outputs[:624]]

response = requests.get(f"{BASE_URL}/invoke-synchro")
encrypted = bytes.fromhex(response.json()['echo'])

print(f"[*] Encrypted flag: {len(encrypted)} bytes")
print(f"[*] Analyzing different offsets...\n")

candidates = []

for offset in range(-100, 300):
    random.setstate((3, tuple(state + [624]), None))
    for _ in range(max(0, 630 - 624 + offset)):
        random.getrandbits(32)

    key_int = random.getrandbits(len(encrypted) * 8)
    key_bytes = key_int.to_bytes(len(encrypted), 'little')
    flag = bytes(a ^ b for a, b in zip(encrypted, key_bytes))

    if b"HTB{" in flag:
        # Count ASCII chars
        ascii_count = sum(1 for b in flag if 32 <= b <= 126)
        printable = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in flag)

        if ascii_count >= 35:  # At least 35 printable chars
            candidates.append((offset, ascii_count, flag, printable))

# Sort by ASCII count
candidates.sort(key=lambda x: x[1], reverse=True)

print("[*] Top candidates by printable character count:\n")
for offset, count, flag_bytes, printable in candidates[:10]:
    print(f"Offset {offset:4d}: {count}/54 ASCII | {printable}")

    # Show hex for non-ASCII parts
    if count < 54:
        print(f"             Hex: {flag_bytes.hex()}")
        print(f"             Bytes: {flag_bytes}\n")

# Try to infer the flag from best candidate
if candidates:
    best = candidates[0]
    print(f"\n[*] BEST CANDIDATE (offset {best[0]}):")
    print(f"    Printable: {best[3]}")
    print(f"    Hex: {best[2].hex()}")

    # Try to infer middle section
    flag_text = best[3]
    if "HTB{r4nd0m_m0dul3_f0r_th3_r3" in flag_text:
        print(f"\n[*] Known prefix found. Analyzing pattern...")
        print(f"    Expected pattern: HTB{{r4nd0m_m0dul3_f0r_th3_r3XXXXX_w1th_Lx3!}}")
        print(f"    What we see: {flag_text}")
