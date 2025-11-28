import json
from decimal import Decimal, getcontext
from fpylll import IntegerMatrix, LLL
from z3 import *

getcontext().prec = 150

def load_samples():
    with open('samples.json', 'r') as f:
        return json.load(f)

def recover_coeffs_lll(lat, lon, south):
    lon_len = len(str(lon))
    lon_dec = Decimal(lon)
    lat_dec = Decimal(lat)
    
    solutions = []
    
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
        
        for i in range(M.nrows):
            row = M[i]
            a = int(row[0])
            b = int(row[1])
            val_c = -(a * x2_dec + b * x_dec)
            c = int(round(val_c))
            
            if a > 0:
                ta, tb, tc = -a, -b, -c
            else:
                ta, tb, tc = a, b, c
                
            if - (2**32) <= ta <= 0 and 0 <= tb < 2**32 and 0 <= tc < 2**32:
                solutions.append((ta, tb, tc, k))
                
    return solutions

def temper(y):
    y = y ^ (y >> 11)
    y = y ^ ((y << 7) & 0x9d2c5680)
    y = y ^ ((y << 15) & 0xefc60000)
    y = y ^ (y >> 18)
    return y

def untemper(y):
    # Z3 untemper
    s = Solver()
    v = BitVec('v', 32)
    # Re-implement temper in Z3
    y1 = v ^ LShR(v, 11)
    y2 = y1 ^ ((y1 << 7) & 0x9d2c5680)
    y3 = y2 ^ ((y2 << 15) & 0xefc60000)
    y4 = y3 ^ LShR(y3, 18)
    
    s.add(y4 == y)
    s.check()
    return s.model()[v].as_long()

def twist(mt):
    mt = list(mt)
    for i in range(624):
        y = (mt[i] & 0x80000000) + (mt[(i+1) % 624] & 0x7fffffff)
        mt[i] = mt[(i+397) % 624] ^ (y >> 1)
        if y % 2 != 0:
            mt[i] = mt[i] ^ 0x9908b0df
    return mt

def main():
    samples = load_samples()
    print(f"[*] Loaded {len(samples)} samples")
    
    outputs = []
    
    # Recover coefficients
    for i, sample in enumerate(samples):
        sol = recover_coeffs_lll(sample['lat'], sample['lon'], sample['south'])
        if not sol:
            print(f"[!] No solution for sample {i}")
            return
        
        # If multiple solutions, pick first for now (or warn)
        if len(sol) > 1:
            # print(f"[!] Multiple solutions for sample {i}: {len(sol)}")
            pass
            
        a, b, c, k = sol[0]
        outputs.extend([-a, b, c])
        
        if len(outputs) >= 630:
            break
            
    print(f"[*] Recovered {len(outputs)} outputs")
    
    # Verify consistency
    # Untemper first 624
    state = [untemper(y) for y in outputs[:624]]
    
    # Twist
    next_state = twist(state)
    
    # Check against remaining outputs
    print("[*] Verifying consistency...")
    errors = 0
    for i in range(len(outputs) - 624):
        predicted = temper(next_state[i])
        actual = outputs[624 + i]
        
        if predicted != actual:
            print(f"[!] Mismatch at offset {624+i}: predicted {predicted}, actual {actual}")
            # This implies error in state indices involved in generating this output
            # output[i] depends on state[i], state[i+1], state[i+397]
            # So mismatch at 0 (624) implies error in state[0], state[1], or state[397]
            errors += 1
        else:
            print(f"[+] Match at offset {624+i}")
            
    if errors == 0:
        print("[+] State is consistent!")
    else:
        print(f"[!] Found {errors} errors")

if __name__ == "__main__":
    main()
