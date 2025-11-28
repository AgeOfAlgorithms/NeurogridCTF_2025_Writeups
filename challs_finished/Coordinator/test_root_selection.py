#!/usr/bin/env python3
"""
Test to verify the root selection logic from shrine.py
This may be the missing constraint causing UNSAT!
"""
import decimal
from decimal import Decimal

def magic(a, b, c):
    """Exact copy from shrine.py"""
    decimal.getcontext().prec = 100
    D = Decimal(b**2 - 4*a*c)
    x1 = (-b + D.sqrt()) / (2*a)
    x2 = (-b - D.sqrt()) / (2*a)
    assert all(a*x**2 + b*x + c < 1e-9 for x in [x1, x2])
    return x1 if b < (2**31 + 2**32)//2 else x2

# Test with two different b values
a_test = -100000
c_test = 500000

# Case 1: b < threshold (should return x1)
b_small = 1000000000  # < 3221225472
x_small = magic(a_test, b_small, c_test)
print(f"b = {b_small} (< threshold)")
print(f"  Returned root: {x_small}")

# Calculate both roots manually
D = Decimal(b_small**2 - 4*a_test*c_test)
x1 = (-b_small + D.sqrt()) / (2*a_test)
x2 = (-b_small - D.sqrt()) / (2*a_test)
print(f"  x1 (+sqrt): {x1}")
print(f"  x2 (-sqrt): {x2}")
print(f"  Magic returned x1: {x_small == x1}")
print()

# Case 2: b >= threshold (should return x2)
b_large = 4000000000  # >= 3221225472
x_large = magic(a_test, b_large, c_test)
print(f"b = {b_large} (>= threshold)")
print(f"  Returned root: {x_large}")

D = Decimal(b_large**2 - 4*a_test*c_test)
x1 = (-b_large + D.sqrt()) / (2*a_test)
x2 = (-b_large - D.sqrt()) / (2*a_test)
print(f"  x1 (+sqrt): {x1}")
print(f"  x2 (-sqrt): {x2}")
print(f"  Magic returned x2: {x_large == x2}")
print()

print("="*60)
print("CRITICAL FINDING:")
print("The server selects which root to return based on b!")
print("Threshold b = (2**31 + 2**32)//2 = 3221225472")
print()
print("Our candidate finder must verify:")
print("1. If b < 3221225472, observed x must equal x1")
print("2. If b >= 3221225472, observed x must equal x2")
print()
print("This is likely why we get UNSAT - many candidates")
print("would return the WRONG root!")
