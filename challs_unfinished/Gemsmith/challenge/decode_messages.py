#!/usr/bin/env python3
"""
Decode all the fullwidth messages from the binary
Author: Claude Code
Purpose: Understand what all the messages say
Created: 2025-11-23
"""

messages = {
    "Banner": "f09f92a0e38080efbca7efbd85efbd8defbd95e38080efbd8eefbd8fe38080efbcb3efbd88efbd8fefbd8befbd95efbd8eefbd89efbd8ee38080efbd97efbd81e38080efbd93efbd81efbd89efbd8befbd99efbd8fefbd95e38080efbd8eefbd8fe38080efbd8befbd85efbd8eefbd8fe38080efbd97efbd8fe38080efbd94efbd93efbd95efbd8befbd95efbd92efbd89efbd8defbd81efbd93efbd95efbc810a",
    "Delete success (0x14e0)": "f09f9791efb88fe38080efbca7efbd85efbd8defbd95e38080efbd97efbd81e38080efbd93efbd81efbd8befbd95efbd8aefbd8fe38080efbd93efbd81efbd92efbd85efbd8defbd81efbd93efbd88efbd89efbd94efbd81",
    "Fail message 1 (0x12f0)": "e29aa0efb88fe38080efbca9efbd8eefbd84efbd85efbd8befbd8befbd95efbd93efbd95e38080efbd97efbd81e38080efbd8defbd81efbd83efbd88efbd89efbd87efbd81efbd94efbd94efbd85efbd89efbd8defbd81efbd93efbd95efbc810a",
    "sword broken (0x1c10)": "f09f92a0e38080efbca7efbd85efbd8defbd95e38080efbd8eefbd8fe38080efbcb3efbd88efbd8fefbd8befbd95efbd8eefbd89efbd8ee38080efbd97efbd81e38080efbd93efbd81efbd89efbd8befbd99efbd8fefbd95e38080efbd8eefbd8fe38080efbd8befbd85efbd8eefbd8fe38080efbd97efbd8fe38080efbd94efbd93efbd95efbd8befbd95efbd92efbd89efbd8defbd81efbd93efbd95efbc810a",
}

for name, hex_data in messages.items():
    try:
        decoded = bytes.fromhex(hex_data).decode('utf-8')
        print(f"\n{name}:")
        print(f"  {decoded}")
    except Exception as e:
        print(f"\n{name}: ERROR - {e}")

# Also let's look at the gem/sword strings
print("\n\n=== SEARCHING FOR KEY STRINGS ===")
import subprocess
result = subprocess.run(['strings', './gemsmith'], capture_output=True, text=True)
for line in result.stdout.split('\n'):
    if any(word in line.lower() for word in ['upgrade', 'forge', 'upgrade', 'complete', 'perfect', 'broken', 'sword', 'ken']):
        print(f"  {line}")
