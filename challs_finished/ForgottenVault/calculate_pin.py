#!/usr/bin/env python3
"""
Script to calculate the PIN that triggers SIGFPE in check_pin function
Author: AI
Purpose: Find the input that causes division by zero
Created: 2025-11-20
Expected result: PIN value that triggers the signal handler
"""

# From the check_pin disassembly:
# eax = input + 0x154f641
# ecx = input - 0x4149
# edx = input + 0xac979988
# ecx = ecx + edx + 1
# eax = eax / ecx (idiv)
#
# For SIGFPE (divide by zero), ecx must be 0:
# (input - 0x4149) + (input + 0xac979988) + 1 = 0
# 2*input - 0x4149 + 0xac979988 + 1 = 0
# 2*input = 0x4149 - 0xac979988 - 1
# 2*input = 0x4149 - 0xac979989

# Calculate in Python with proper signed arithmetic
val1 = 0x4149
val2 = 0xac979989

# Since we're dealing with signed integers, we need to be careful
# val2 is actually negative in 32-bit signed representation
# 0xac979989 as signed 32-bit = -1399923319

# But wait, the assembly uses 64-bit registers
# Let me trace through more carefully

# Actually looking at the assembly:
# movslq converts 32-bit to 64-bit signed
# So the values are treated as 32-bit signed integers

# Let's calculate:
# denominator = (input - 0x4149) + (input + 0xac979988) + 1
# For 32-bit signed arithmetic:
# denominator = 2*input + (0xac979988 - 0x4149 + 1)

val_sum = 0xac979988 - 0x4149 + 1

# Convert to signed 32-bit
if val_sum >= 0x80000000:
    val_sum_signed = val_sum - 0x100000000
else:
    val_sum_signed = val_sum

print(f"Sum value: 0x{val_sum:x} = {val_sum_signed}")

# For denominator = 0:
# 2*input + val_sum = 0
# 2*input = -val_sum
# input = -val_sum / 2

pin = -val_sum_signed // 2

# Convert to 32-bit signed representation
if pin < -0x80000000:
    pin = pin + 0x100000000
elif pin >= 0x80000000:
    pin = pin - 0x100000000

print(f"Calculated PIN: {pin}")
print(f"Calculated PIN (hex): 0x{pin & 0xffffffff:x}")

# Verify the calculation
denominator = 2 * pin + val_sum_signed
print(f"Verification - denominator: {denominator}")
