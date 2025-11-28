#!/usr/bin/env python3
import json
import time
import requests
import random
from decimal import Decimal, getcontext
from fpylll import IntegerMatrix, LLL
from z3 import *

# Set precision high enough
getcontext().prec = 150

# Challenge connection
# Challenge connection
HOST = "154.57.164.81"
PORT = 32397
BASE_URL = f"http://{HOST}:{PORT}"

def load_samples():
    with open('samples.json', 'r') as f:
        return json.load(f)

def recover_coeffs_lll(lat, lon, south):
    lon_len = len(str(lon))
    lon_dec = Decimal(lon)
    lat_dec = Decimal(lat)
    
    # Try different paddings
    for k in range(10):
        scale = Decimal(10) ** (lon_len + k)
        val_abs = lat_dec + (lon_dec / scale)
        
        if south == 1:
            x_val = -val_abs
        else:
            x_val = val_abs
            
        K = 10**120
        x_dec = x_val
        x2_dec = x_val * x_val
        
        X = int(x_dec * K)
        X2 = int(x2_dec * K)
        KK = int(K)
        
        M = IntegerMatrix(3, 3)
        M[0, 0] = 1
        M[0, 1] = 0
        M[0, 2] = X2
        M[1, 0] = 0
        M[1, 1] = 1
        M[1, 2] = X
        M[2, 0] = 0
        M[2, 1] = 0
        M[2, 2] = KK
        
        LLL.reduction(M)
        
        # Check rows
        for i in range(M.nrows):
            row = M[i]
            a = int(row[0])
            b = int(row[1])
            
            # c ≈ -(a*x^2 + b*x)
            val_c = -(a * x2_dec + b * x_dec)
            c = int(round(val_c))
            
            # Normalize signs
            if a > 0:
                ta, tb, tc = -a, -b, -c
            else:
                ta, tb, tc = a, b, c
                
            # Check ranges
            if - (2**32) <= ta <= 0 and 0 <= tb < 2**32 and 0 <= tc < 2**32:
                return ta, tb, tc
                
    return None

def temper(y):
    y = y ^ LShR(y, 11)
    y = y ^ ((y << 7) & 0x9d2c5680)
    y = y ^ ((y << 15) & 0xefc60000)
    y = y ^ LShR(y, 18)
    return y

def untemper(y):
    # Z3 untemper
    s = Solver()
    v = BitVec('v', 32)
    res = temper(v)
    s.add(res == y)
    s.check()
    return s.model()[v].as_long()

def recover_mt19937_state(outputs):
    print(f"[*] Recovering MT19937 state from {len(outputs)} outputs...")
    
    # Untemper outputs to get state values
    untempered = []
    for y in outputs:
        val = untemper(y)
        untempered.append(val)
        
    return untempered

def decrypt_flag(state):
    print("[*] Attempting to decrypt flag...")
    
    # Take first 624 values for state
    mt_state = state[:624]
    
    # Set state with index 624 (trigger twist on next call)
    state_tuple = tuple(mt_state + [624])
    random.setstate((3, state_tuple, None))
    
    # Fast forward
    # Fast forward
    # We might be off by a few outputs
    # Try a range of offsets
    
    # Fetch encrypted flag first
    print("[*] Fetching encrypted flag...")
    try:
        response = requests.get(f"{BASE_URL}/invoke-synchro")
        data = response.json()
        encrypted_hex = data['echo']
        encrypted = bytes.fromhex(encrypted_hex)
    except Exception as e:
        print(f"[!] Error fetching flag: {e}")
        return None

    current_idx = 624
    target_idx = len(state)
    
    # We want to start from target_idx, but maybe +/- some
    # The state tuple has the index at the end.
    # We can just consume from the generator.
    
    # Let's try offsets from -50 to +50 relative to expected
    expected_fwd = target_idx - current_idx
    
    print(f"[*] Brute-forcing offsets (expected fwd: {expected_fwd})...")
    
    for offset in range(-50, 50):
        # Reset state
        state_tuple = tuple(mt_state + [624])
        random.setstate((3, state_tuple, None))
        
        # Calculate how many to consume
        to_consume = expected_fwd + offset
        
        if to_consume < 0:
            continue
            
        for _ in range(to_consume):
            random.getrandbits(32)
            
        # Get XOR key
        key_bits = len(encrypted) * 8
        key_int = random.getrandbits(key_bits)
        key_bytes = key_int.to_bytes(len(encrypted), 'little')
        
        # XOR
        flag = bytes(a ^ b for a, b in zip(encrypted, key_bytes))
        
        if b"HTB{" in flag:
            return flag
            
    return None

def collect_samples(count):
    print(f"[*] Collecting {count} samples from {BASE_URL}...")
    samples = []
    for i in range(count):
        try:
            response = requests.get(f"{BASE_URL}/read-star-coordinates", timeout=5)
            if response.status_code == 200:
                samples.append(response.json())
                if (i+1) % 10 == 0:
                    print(f"  Collected {i+1}/{count}...")
            else:
                print(f"[!] Error collecting sample {i}: Status {response.status_code}")
        except Exception as e:
            print(f"[!] Connection error: {e}")
            return samples
    return samples

def recover_coeffs_lll_all(lat, lon, south):
    lon_len = len(str(lon))
    lon_dec = Decimal(lon)
    lat_dec = Decimal(lat)
    
    candidates = []
    
    # Try different paddings - expanded range
    for k in range(-2, 15):
        scale = Decimal(10) ** (lon_len + k)
        val_abs = lat_dec + (lon_dec / scale)
        
        if south == 1:
            x_val = -val_abs
        else:
            x_val = val_abs
            
        K = 10**120
        x_dec = x_val
        x2_dec = x_val * x_val
        
        X = int(x_dec * K)
        X2 = int(x2_dec * K)
        KK = int(K)
        
        M = IntegerMatrix(3, 3)
        M[0, 0] = 1
        M[0, 1] = 0
        M[0, 2] = X2
        M[1, 0] = 0
        M[1, 1] = 1
        M[1, 2] = X
        M[2, 0] = 0
        M[2, 1] = 0
        M[2, 2] = KK
        
        LLL.reduction(M)
        
        # Check all rows
        for i in range(M.nrows):
            row = M[i]
            a = int(row[0])
            b = int(row[1])
            
            # c ≈ -(a*x^2 + b*x)
            val_c = -(a * x2_dec + b * x_dec)
            c = int(round(val_c))
            
            # Normalize signs
            if a > 0:
                ta, tb, tc = -a, -b, -c
            else:
                ta, tb, tc = a, b, c
                
            # Check ranges
            if - (2**32) <= ta <= 0 and 0 <= tb < 2**32 and 0 <= tc < 2**32:
                # Check error - relaxed threshold
                err = abs(Decimal(ta)*x2_dec + Decimal(tb)*x_dec + Decimal(tc))
                if err < 1e-8: # Relaxed from 1e-10
                    candidates.append((ta, tb, tc))
    
    # Remove duplicates
    unique_candidates = []
    seen = set()
    for cand in candidates:
        if cand not in seen:
            unique_candidates.append(cand)
            seen.add(cand)
            
    return unique_candidates

def main():
    # Check connection
    try:
        requests.get(f"{BASE_URL}/read-star-coordinates", timeout=2)
        print("[*] Connected to server!")
        # Collect fresh samples
        samples = collect_samples(220) # Need ~210, get a few more
    except:
        print("[!] Could not connect to server. Using local samples.json if available...")
        try:
            samples = load_samples()
            print(f"[*] Loaded {len(samples)} samples from file")
        except:
            print("[!] No samples available.")
            return

    if not samples:
        print("[!] No samples collected.")
        return
    
    # Recover coefficients
    # We suspect samples 2, 3, 135 might be bad.
    # Let's get all candidates for them.
    
    sample_candidates = []
    print("[*] Recovering coefficients...")
    
    for i, sample in enumerate(samples):
        cands = recover_coeffs_lll_all(sample['lat'], sample['lon'], sample['south'])
        if not cands:
            print(f"[!] Failed to recover coeffs for sample {i}")
            # If we fail on early samples, we can't recover state
            if i < 210:
                print("[!] Critical failure.")
                return
            continue
        sample_candidates.append(cands)
        if len(sample_candidates) >= 210:
            break
            
    print(f"[*] Recovered candidates for {len(sample_candidates)} samples")
    
    # Identify ambiguous samples
    ambiguous = []
    for i, cands in enumerate(sample_candidates):
        if len(cands) > 1:
            print(f"[*] Sample {i} has {len(cands)} candidates")
            ambiguous.append(i)
            
    # Force check samples 2, 3, 135 even if they have 1 candidate (maybe the *wrong* one was found first?)
    # Actually recover_coeffs_lll_all returns ALL valid ones found across paddings.
    # If it only returns 1, then LLL only found 1.
    
    # Let's try to construct state with best candidates first
    # Then try alternatives for 2, 3, 135 if available
    
    import itertools
    
    # KPA Approach
    print("[*] Attempting Known Plaintext Attack on Sample 135...")
    
    # We need S_0[8] and S_0[9]
    # Sample 2 gives 6,7,8. S_0[8] is the 3rd output of Sample 2.
    # Sample 3 gives 9,10,11. S_0[9] is the 1st output of Sample 3.
    
    # Get candidates for Sample 2 and 3
    cands2 = recover_coeffs_lll_all(samples[2]['lat'], samples[2]['lon'], samples[2]['south'])
    cands3 = recover_coeffs_lll_all(samples[3]['lat'], samples[3]['lon'], samples[3]['south'])
    
    if not cands2 or not cands3:
        print("[!] Failed to get candidates for Sample 2 or 3")
        return
        
    # We assume the first candidate is correct for now (usually is for simple cases)
    # S_0[8] = -a from Sample 2 (index 2) -> cands2[0][0] is a, so -a is -cands2[0][0]
    # Wait, outputs are [-a, b, c].
    # Sample 2 outputs: [-a2, b2, c2]. S_0[6]=-a2, S_0[7]=b2, S_0[8]=c2.
    # Ah! S_0[8] is c2!
    
    # Sample 3 outputs: [-a3, b3, c3]. S_0[9]=-a3.
    
    s0_8 = cands2[0][2]
    s0_9 = -cands3[0][0]
    
    # We want to find S_0[405].
    # S_0[405] comes from Sample 135.
    # Sample 135 outputs: [-a135, b135, c135].
    # S_0[405] = -a135.
    
    # Target Word 8 of key.
    # Key[8] = Encrypted[8] ^ Plaintext[8]
    # Key[8] = temper(S_1[8])
    # We can untemper Key[8] to get S_1[8].
    
    # Plaintext guesses
    guesses = [
        b"_0xdeadbeef_",
        b"_0xcafebabe_",
        b"_0x1337c0de_",
        b"_0x13371337_",
        b"_0x8badf00d_",
        b"_0xfeedface_",
        b"_0x00000000_",
        b"_0xffffffff_",
        b"_by_l4tt1c3_",
        b"_using_LLL!_",
        b"_w1th_m4th!_",
        b"_in_pyth0n!_"
    ]
    
    # Fetch encrypted flag bytes 32-36 (Word 8)
    if 'encrypted_flag_bytes' not in globals():
        try:
            print("[*] Fetching encrypted flag...")
            response = requests.get(f"{BASE_URL}/invoke-synchro")
            data = response.json()
            global encrypted_flag_bytes
            encrypted_flag_bytes = bytes.fromhex(encrypted_hex)
        except:
            return

    enc_word8_bytes = encrypted_flag_bytes[32:36]
    enc_word8 = int.from_bytes(enc_word8_bytes, 'little')
    
    for guess in guesses:
        # Take first 4 bytes of guess for Word 8
        pt_word8_bytes = guess[:4]
        pt_word8 = int.from_bytes(pt_word8_bytes, 'little')
        
        key_word8 = enc_word8 ^ pt_word8
        
        # Untemper to get S_1[8]
        s1_8 = untemper(key_word8)
        
        # Solve for S_0[405]
        # S_1[8] = S_0[405] ^ (y >> 1) ^ (magic if y odd)
        # y = (S_0[8] & 0x80000000) + (S_0[9] & 0x7fffffff)
        
        y = (s0_8 & 0x80000000) + (s0_9 & 0x7fffffff)
        twist_part = (y >> 1)
        if y % 2 != 0:
            twist_part ^= 0x9908b0df
            
        s0_405 = s1_8 ^ twist_part
        
        # s0_405 is -a for Sample 135.
        # So a = -s0_405.
        target_a = -s0_405
        
        # Check if this 'a' is valid for Sample 135
        # We can check if there exists b, c such that a*x^2 + b*x + c approx 0
        # We can use LLL with fixed a?
        # Or just check if recover_coeffs_lll_all finds it if we force it?
        
        # Let's just check if it's "plausible"
        # i.e. is it a 32-bit integer?
        # s0_405 is from MT state, so it is 32-bit unsigned.
        # a = -s0_405. So a is negative 32-bit.
        # This matches our expectation.
        
        print(f"[*] Testing guess '{guess.decode()}' -> a = {target_a}")
        
        # Check against Sample 135
        lat = samples[135]['lat']
        lon = samples[135]['lon']
        south = samples[135]['south']
        
        lon_len = len(str(lon))
        lon_dec = Decimal(lon)
        lat_dec = Decimal(lat)
        
        # Try to find b, c for this a
        # c = -(a*x^2 + b*x)
        # We can iterate b? No, b is 32-bit.
        # But we can use LLL to find b, c given a.
        # Lattice:
        # 1 0 x
        # 0 1 1
        # Target vector: (b, c) such that b*x + c approx -a*x^2
        # This is 2D LLL.
        
        # Or just reuse recover_coeffs_lll but look for specific a?
        # No, that's inefficient.
        
        # Let's just assume it's correct and try to decrypt the rest of the flag
        # If the guess is right, the rest of the flag should be readable.
        
        # Construct state
        # We need to fill in the outputs list
        # We can reuse the 'outputs' list from before, but patch Sample 135
        
        # Re-build outputs list
        outputs = []
        for i, sample in enumerate(samples):
            if i == 135:
                # Use our deduced a
                # We need b and c too for the state recovery to be complete?
                # Actually, S_0[405] is -a.
                # S_0[406] is b.
                # S_0[407] is c.
                # We need b and c to get S_1[9] and S_1[10] (which are also garbage).
                # But we can deduce them too!
                
                # Deduce b from Word 9
                # Key[9] = Encrypted[9] ^ Plaintext[9]
                # S_1[9] = untemper(Key[9])
                # S_1[9] = S_0[406] ^ (y' >> 1) ^ ...
                # y' = (S_0[9] & 0x80000000) + (S_0[10] & 0x7fffffff)
                # S_0[9] is known (Sample 3). S_0[10] is known (Sample 3).
                # So we can deduce S_0[406] (which is b).
                
                # Deduce c from Word 10
                # ... S_0[407] (which is c).
                
                # Let's do this!
                
                # Word 9
                pt_word9_bytes = guess[4:8]
                pt_word9 = int.from_bytes(pt_word9_bytes, 'little')
                key_word9 = int.from_bytes(encrypted_flag_bytes[36:40], 'little') ^ pt_word9
                s1_9 = untemper(key_word9)
                
                # S_0[9] = -a3 (Sample 3, index 3, output 0) -> -cands3[0][0]
                # S_0[10] = b3 (Sample 3, index 3, output 1) -> cands3[0][1]
                s0_10 = cands3[0][1]
                
                y2 = (s0_9 & 0x80000000) + (s0_10 & 0x7fffffff)
                twist_part2 = (y2 >> 1)
                if y2 % 2 != 0:
                    twist_part2 ^= 0x9908b0df
                s0_406 = s1_9 ^ twist_part2 # This is b
                
                # Word 10
                pt_word10_bytes = guess[8:12]
                pt_word10 = int.from_bytes(pt_word10_bytes, 'little')
                key_word10 = int.from_bytes(encrypted_flag_bytes[40:44], 'little') ^ pt_word10
                s1_10 = untemper(key_word10)
                
                # S_0[10] is known. S_0[11] is c3 (Sample 3, output 2) -> cands3[0][2]
                s0_11 = cands3[0][2]
                
                y3 = (s0_10 & 0x80000000) + (s0_11 & 0x7fffffff)
                twist_part3 = (y3 >> 1)
                if y3 % 2 != 0:
                    twist_part3 ^= 0x9908b0df
                s0_407 = s1_10 ^ twist_part3 # This is c
                
                outputs.extend([target_a, s0_406, s0_407]) # -a, b, c? No, outputs are [-a, b, c]
                # target_a is -s0_405. So it is 'a'.
                # outputs list stores [-a, b, c].
                # So we append [s0_405, s0_406, s0_407].
                # Wait, previous code: outputs.extend([raw_a, raw_b, raw_c])
                # raw_a = -a.
                # s0_405 IS -a.
                # So append [s0_405, s0_406, s0_407].
                # Correct.
                
            else:
                # Use existing logic for other samples
                cands = recover_coeffs_lll_all(samples[i]['lat'], samples[i]['lon'], samples[i]['south'])
                if not cands:
                    continue
                a, b, c = cands[0]
                outputs.extend([-a, b, c])
                
            if len(outputs) >= 630:
                break
                
        # Recover state
        if len(outputs) < 624:
            continue
            
        state = recover_mt19937_state(outputs)
        
        # Decrypt flag
        flag = decrypt_flag(state)
        if flag:
            try:
                flag_str = flag.decode()
                print(f"[+] Decrypted with guess '{guess.decode()}': {flag_str}")
                if "HTB{" in flag_str and all(32 <= b <= 126 for b in flag):
                    print(f"[+] SUCCESS! Flag found.")
                    return
            except:
                pass



if __name__ == "__main__":
    main()
