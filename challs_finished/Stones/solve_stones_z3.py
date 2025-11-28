"""
Script: solve_stones_z3.py
Author: Antigravity
Purpose: Recover MT19937 PRNG state from partial outputs using Z3, then find the target stone and decrypt the flag.
Assumptions:
- Python's random.getrandbits(24) returns the top 24 bits of the 32-bit output.
- We have enough consecutive outputs (from decrypted_stones.json) to recover the state.
- The target stone is within the first 2^20 generated stones.

Usage: conda run -n ctf python solve_stones_z3.py
"""

import json
import random
import time
from z3 import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Configuration
DECRYPTED_STONES_FILE = "all_decrypted_stones.json"
ORACLE_FILE = "crypto_stones/oracle.txt"
STONES_COUNT = 2**20

def load_data():
    with open(DECRYPTED_STONES_FILE, 'r') as f:
        stones = json.load(f)
    # Sort by index to ensure correct sequence
    stones.sort(key=lambda x: x['index'])
    
    # Debug: Limit stones
    limit = 130 # Try 130
    print(f"[*] Limiting to first {limit} stones.")
    stones = stones[:limit]
    
    return stones

def load_target():
    with open(ORACLE_FILE, 'r') as f:
        content = f.read()
    
    sigil_a_line = [l for l in content.splitlines() if l.startswith("sigil_a")][0]
    seal_line = [l for l in content.splitlines() if l.startswith("seal")][0]
    
    target_sigil_a = int(sigil_a_line.split("=")[1].strip())
    target_seal = bytes.fromhex(seal_line.split("=")[1].strip())
    
    return target_sigil_a, target_seal

def recover_state(stones):
    print(f"[*] Recovering PRNG state from {len(stones)} stones...")
    
    # Collect outputs in order
    # Each stone: 4 sigil_a, 4 sigil_b, 1 echo
    outputs = []
    for stone in stones:
        # sigil_a (128 bits, LSB first)
        val = stone['sigil_a']
        for _ in range(4):
            outputs.append(("full", val & 0xFFFFFFFF))
            val >>= 32
            
        # sigil_b (128 bits, LSB first)
        val = stone['sigil_b']
        for _ in range(4):
            outputs.append(("full", val & 0xFFFFFFFF))
            val >>= 32
            
        # echo (24 bits, TOP 24 bits of 32-bit output)
        echo = stone['echo']
        outputs.append(("partial", echo))

    print(f"[*] Total outputs collected: {len(outputs)}")
    
    # Z3 Solver
    solver = Solver()
    n = 624
    MT = [BitVec(f'MT_{i}', 32) for i in range(n)]
    
    # Helper for twist
    def twist(m):
        # MT19937 updates the state in-place.
        # We must simulate this behavior.
        mt_tmp = list(m) # Copy of symbolic variables
        
        for i in range(624):
            y = (mt_tmp[i] & 0x80000000) + (mt_tmp[(i+1) % 624] & 0x7fffffff)
            val = mt_tmp[(i+397) % 624] ^ z3.LShR(y, 1)
            val = z3.If(y & 1 == 1, val ^ 0x9908b0df, val)
            mt_tmp[i] = val
            
        return mt_tmp
        
    # Helper for temper
    def temper(y):
        y = y ^ z3.LShR(y, 11)
        y = y ^ ((y << 7) & 0x9d2c5680)
        y = y ^ ((y << 15) & 0xefc60000)
        y = y ^ z3.LShR(y, 18)
        return y

    # We only need enough constraints to solve for the 624 state variables.
    # 624 outputs should be enough if they were all full.
    # We have partials every 9th output.
    # Let's use all available outputs up to a reasonable limit to ensure unique solution.
    # 80 stones = 720 outputs.
    
    current_MT = list(MT)
    
    # Expand symbolic state to cover all outputs
    while len(current_MT) < len(outputs):
        # Generate next batch of 624 values
        # The twist function takes the *current* state (last 624 values)
        # and returns the *next* state (next 624 values).
        next_batch = twist(current_MT[-624:])
        current_MT.extend(next_batch)
    
    print("[*] Building Z3 constraints...")
    start_time = time.time()
    
    for k, (type, val) in enumerate(outputs):
        # Tempering
        y = temper(current_MT[k])
        
        if type == "full":
            solver.add(y == val)
        else:
            # val is top 24 bits
            solver.add(z3.LShR(y, 8) == val)
            
    print(f"[*] Constraints built in {time.time() - start_time:.2f}s. Solving...")
    
    if solver.check() == sat:
        print("[*] SAT! Solution found.")
        model = solver.model()
        recovered_state = [model[MT[i]].as_long() for i in range(n)]
        
        # Verify against Stone 0
        print("[*] Verifying recovered state against Stone 0...")
        state_tuple = tuple(recovered_state + [0])
        random.setstate((3, state_tuple, None))
        
        # Generate Stone 0
        s0_sigil_a = random.getrandbits(128)
        s0_sigil_b = random.getrandbits(128)
        s0_echo = random.getrandbits(24)
        
        print(f"   Stone 0 sigil_a (Actual): {stones[0]['sigil_a']}")
        print(f"   Stone 0 sigil_a (Pred)  : {s0_sigil_a}")
        
        if s0_sigil_a == stones[0]['sigil_a']:
            print("[+] State verification SUCCESSFUL.")
            return recovered_state
        else:
            print("[-] State verification FAILED. Predictions do not match.")
            # Debug: Check if it matches later stones?
            # Maybe index is not 0?
            return None
    else:
        print("[!] UNSAT. Failed to recover state.")
        return None

def find_target_and_decrypt(initial_state, target_sigil_a, target_seal):
    print("[*] Initializing Python PRNG with recovered state...")
    
    # Set Python's random state
    # state tuple: (3, (MT_array + index), None)
    # We recovered the state at the BEGINNING of the sequence (index 0)
    # So we append 624 as the index (forcing a twist immediately? No wait)
    # The state we recovered is the MT array *before* the first output?
    # Or is it the array *after* the twist?
    
    # In Z3 we assumed MT[0]...MT[623] are the values used for the first 624 outputs.
    # This corresponds to the state *after* a twist, with index=0.
    # So we should set index=0?
    # Python's setstate takes the full tuple.
    # The internal state array has 624 elements.
    # The index is the last element of the tuple (actually it's not in the tuple passed to setstate directly like that, let's check)
    
    # random.getstate() returns (3, tuple(624 ints), None) usually.
    # Wait, let's check getstate format.
    # It returns (version, internal_state, gauss_next)
    # internal_state is a tuple of 624 ints + index.
    # So 625 ints total.
    
    # If we set index=624, it forces a twist on next call.
    # But we solved for the state that generates the *current* sequence starting at 0.
    # So we should set index=0?
    # Actually, if index=0, it uses MT[0].
    # So yes, index should be 0.
    # But Python's random module might use index=624 to mean "exhausted, twist now".
    # If we want to start at MT[0], we set index=0?
    # Let's verify this quickly or just try both.
    # Actually, we can just use the `random` module to simulate.
    
    state_tuple = tuple(initial_state + [0]) # 624 ints + index=0
    random.setstate((3, state_tuple, None))
    
    # Fast forward through the stones we already processed?
    # No, the target stone could be anywhere.
    # But we know the target stone index is likely NOT in the first 80 (since we decrypted them and didn't find it? Or maybe we did?)
    # The challenge says "One stone contains our target sigil_a value".
    # We need to find WHICH stone.
    
    print("[*] Searching for target stone...")
    
    # We need to simulate 2^20 stones.
    # Each stone consumes: 4 + 4 + 1 = 9 calls to getrandbits(32) (effectively)
    # Wait, getrandbits(128) calls getrandbits(32) 4 times.
    # getrandbits(24) calls getrandbits(32) 1 time.
    # So 9 calls per stone.
    
    # Optimization: We only need to check sigil_a (first 4 calls).
    # If match, we get sigil_b (next 4 calls).
    # If not match, we skip 5 calls (4 for sigil_b + 1 for echo).
    
    # Actually, we can just run the loop.
    
    found = False
    target_stone_idx = -1
    target_sigil_b = 0
    
    # Store all sigil_a values
    print("[*] Generating all stones and storing sigil_a...")
    all_sigil_a = []
    
    # Reset to ensure we start from 0
    random.setstate((3, state_tuple, None))

    for i in range(STONES_COUNT):
        # sigil_a
        sigil_a = random.getrandbits(128)
        all_sigil_a.append(sigil_a)
        
        # sigil_b
        random.getrandbits(128)
        # echo
        random.getrandbits(24)
        
        if i % 100000 == 0:
            print(f"Generated {i} stones...", end='\r')
            
    print(f"Generated {STONES_COUNT} stones.")
    
    # Verify last stone
    last_sigil_a = all_sigil_a[-1]
    print(f"[*] Last Stone sigil_a (Sim): {last_sigil_a}")
    print(f"[*] Last Stone sigil_a (Act): 291677594953433929998001845514464549369")
    
    if last_sigil_a == 291677594953433929998001845514464549369:
        print("[+] Simulation matches LAST stone! Simulation is correct.")
    else:
        print("[-] Simulation mismatch at LAST stone.")
        
    # Check target again
    print(f"[*] Checking for target: {target_sigil_a}")
    if target_sigil_a in all_sigil_a:
        idx = all_sigil_a.index(target_sigil_a)
        print(f"[!] FOUND TARGET at index {idx}!")
        
        # Regenerate sigil_b
        print("[*] Regenerating sigil_b...")
        random.setstate((3, state_tuple, None))
        for _ in range(idx):
            random.getrandbits(128)
            random.getrandbits(128)
            random.getrandbits(24)
            
        sa = random.getrandbits(128)
        target_sigil_b = random.getrandbits(128)
        print(f"    Target Sigil B: {target_sigil_b}")
        
        # Decrypt
        print("[*] Decrypting flag...")
        for byteorder in ['big', 'little']:
            try:
                key = target_sigil_b.to_bytes(16, byteorder)
                cipher = AES.new(key, AES.MODE_ECB)
                flag = unpad(cipher.decrypt(target_seal), 16)
                print(f"[+] FLAG ({byteorder}): {flag.decode()}")
                return flag.decode()
            except Exception as e:
                print(f"[-] Failed with {byteorder}: {e}")
    else:
        print("[!] Target NOT found in list.")


if __name__ == "__main__":
    stones = load_data()
    target_sigil_a, target_seal = load_target()
    
    state = recover_state(stones)
    if state:
        find_target_and_decrypt(state, target_sigil_a, target_seal)
