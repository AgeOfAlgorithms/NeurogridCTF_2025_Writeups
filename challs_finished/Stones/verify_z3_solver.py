from z3 import *
import random

def verify_z3_logic():
    # 1. Generate a small sequence of random numbers
    seed = 12345
    random.seed(seed)
    
    # Simulate 5 stones (45 outputs)
    # Each stone: 4 for sigil_a, 4 for sigil_b, 1 for echo
    outputs = []
    for _ in range(5):
        # sigil_a (4 outputs)
        for _ in range(4):
            outputs.append(("full", random.getrandbits(32)))
        # sigil_b (4 outputs)
        for _ in range(4):
            outputs.append(("full", random.getrandbits(32)))
        # echo (1 partial output)
        echo = random.getrandbits(24)
        outputs.append(("partial", echo))

    print(f"Generated {len(outputs)} outputs for verification.")

    # 2. Setup Z3 Solver
    solver = Solver()
    
    # MT19937 Constants
    w, n, m, r = 32, 624, 397, 31
    a = 0x9908B0DF
    u, d = 11, 0xFFFFFFFF
    s, b = 7, 0x9D2C5680
    t, c = 15, 0xEFC60000
    l = 18
    f = 1812433253

    # Symbolic state (MT array)
    MT = [BitVec(f'MT_{i}', w) for i in range(n)]
    
    # Initialize state from seed (standard MT19937 init)
    # We don't know the seed in the real challenge, but we are solving for the state.
    # In the challenge, we solve for the state at index 0 of our sequence.
    # Here, let's try to solve for the initial state MT[0..623] given the outputs.
    
    # Wait, we need 624 outputs to recover the state fully. 
    # With 5 stones we only have 45 outputs. That's not enough to recover the full state.
    # We need at least 624 outputs.
    # Let's generate enough outputs.
    
    random.seed(seed)
    outputs = []
    # We need ~70 stones to get > 624 outputs
    for _ in range(75):
        for _ in range(4):
            outputs.append(("full", random.getrandbits(32)))
        for _ in range(4):
            outputs.append(("full", random.getrandbits(32)))
        echo = random.getrandbits(24)
        outputs.append(("partial", echo))
        
    print(f"Generated {len(outputs)} outputs (need > 624).")
    
    # We are solving for the state at the BEGINNING of this sequence.
    # Let's call the state at step k as state_k.
    # But MT19937 state is 624 integers.
    # The outputs are generated from the state.
    # output_k = temper(MT[k])
    # If k >= 624, MT[k] is generated from previous MT values.
    
    # Logic:
    # We have a symbolic initial state MT[0]...MT[623].
    # For k = 0 to len(outputs)-1:
    #   If k < 624:
    #     val = MT[k]
    #   Else:
    #     # Twist
    #     y = (MT[k-n] & 0x80000000) | (MT[k-n+1] & 0x7FFFFFFF)
    #     val = MT[k-m] ^ (LShR(y, 1)) ^ If(y & 1 == 1, a, 0)
    #     # We need to extend our symbolic MT array as we go
    #     MT.append(val)
    
    #   # Tempering
    #   y = MT[k]
    #   y = y ^ (LShR(y, u) & d)
    #   y = y ^ ((y << s) & b)
    #   y = y ^ ((y << t) & c)
    #   y = y ^ (LShR(y, l))
    
    #   # Constraint
    #   type, known_val = outputs[k]
    #   if type == "full":
    #       solver.add(y == known_val)
    #   else:
    #       # known_val is top 24 bits
    #       # y >> 8 == known_val
    #       solver.add(LShR(y, 8) == known_val)

    # Optimization: We only need to define MT up to the max index we access.
    # And we can process constraints in batches.
    
    print("Building constraints...")
    
    # Helper for tempering
    def temper(y):
        y = y ^ (LShR(y, u) & d)
        y = y ^ ((y << s) & b)
        y = y ^ ((y << t) & c)
        y = y ^ (LShR(y, l))
        return y

    current_MT = list(MT) # Copy of symbolic variables
    
    for k, (type, known_val) in enumerate(outputs):
        if k >= n:
            # Generate next state value (Twist)
            # We need to generate MT[k] based on MT[k-n], MT[k-n+1], MT[k-m]
            # But wait, the standard implementation generates the WHOLE array every 624 steps.
            # However, it's equivalent to generating one by one if we index correctly.
            # MT[k] = MT[k-n] ...
            # Actually, let's stick to the index logic.
            # The generator produces outputs from MT[0], MT[1], ... MT[623], then twists and produces MT[624]...
            # So for k >= 624, we define MT[k] symbolically.
            
            kk = k - n
            y = (current_MT[k-n] & 0x80000000) | (current_MT[k-n+1] & 0x7FFFFFFF)
            # Z3 If is strictly boolean, but we can use arithmetic
            # val = current_MT[k-m] ^ (LShR(y, 1)) ^ If(y & 1 == 1, a, 0)
            # BitVecVal(a, 32) * (y & 1)
            
            # Correct twist logic in Z3:
            twist_val = current_MT[k-m] ^ LShR(y, 1)
            is_odd = (y & 1) == 1
            final_val = If(is_odd, twist_val ^ a, twist_val)
            current_MT.append(final_val)
        
        # Tempering and constraint
        y = temper(current_MT[k])
        
        if type == "full":
            solver.add(y == known_val)
        else:
            solver.add(LShR(y, 8) == known_val)

    print("Solving...")
    if solver.check() == sat:
        print("SAT! Solution found.")
        model = solver.model()
        
        # Verify the first few values
        recovered_state = [model[MT[i]].as_long() for i in range(n)]
        
        # Check against actual random state?
        # We can't easily get the internal state from Python's random module directly without C-level access.
        # But we can predict the NEXT value and see if it matches.
        
        # Predict next value (index = len(outputs))
        k = len(outputs)
        # We need to compute MT[k]
        # We can use our recovered state to simulate.
        
        # Let's just use a Python MT19937 implementation to verify
        class MT19937:
            def __init__(self, state):
                self.MT = list(state)
                self.index = 624
            
            def extract_number(self):
                if self.index >= 624:
                    self.twist()
                
                y = self.MT[self.index]
                y = y ^ ((y >> 11) & 0xFFFFFFFF)
                y = y ^ ((y << 7) & 0x9D2C5680)
                y = y ^ ((y << 15) & 0xEFC60000)
                y = y ^ (y >> 18)
                
                self.index += 1
                return y & 0xFFFFFFFF
            
            def twist(self):
                for i in range(624):
                    y = (self.MT[i] & 0x80000000) + (self.MT[(i+1) % 624] & 0x7FFFFFFF)
                    self.MT[i] = self.MT[(i+397) % 624] ^ (y >> 1)
                    if y % 2 != 0:
                        self.MT[i] = self.MT[i] ^ 0x9908B0DF
                self.index = 0

        # Initialize our predictor with the recovered state
        # Note: The recovered state corresponds to the state BEFORE the first output was generated.
        # So we should set index = 0.
        predictor = MT19937(recovered_state)
        predictor.index = 0
        
        # Fast forward through the outputs we consumed
        for _ in range(len(outputs)):
            predictor.extract_number()
            
        # Predict the next value
        predicted_next = predictor.extract_number()
        
        # Actual next value
        actual_next = random.getrandbits(32)
        
        print(f"Predicted next: {predicted_next}")
        print(f"Actual next:    {actual_next}")
        
        if predicted_next == actual_next:
            print("SUCCESS: State recovered and prediction matches!")
        else:
            print("FAIL: Prediction mismatch.")
            
    else:
        print("UNSAT: Could not find solution.")

if __name__ == "__main__":
    verify_z3_logic()
