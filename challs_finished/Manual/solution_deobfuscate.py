#!/usr/bin/env python3
"""
Analyze the full PowerShell command structure
Author: AI Assistant
Created: 2025-11-20
Purpose: Extract and analyze the complete PowerShell command
Expected: Find the $s= base64 payload and decode it
Result: TBD
"""

import re

# Read batch file
with open('tradesman_manual.bat', 'r') as f:
    lines = f.readlines()

# Extract variables using correct regex
variables = {}
for i, line in enumerate(lines, 1):
    if '!qoz!' in line and '=' in line:
        match = re.search(r'!qoz!\s+%([^%]+)%([^%])%\1%([^%])%\1%([^%])%\1%=(.+)', line)
        if match:
            var_name = match.group(2) + match.group(3) + match.group(4)
            content = match.group(5).strip()
            variables[var_name] = content

print(f"Extracted {len(variables)} variables")

# Get line 125 order
line125 = lines[124]
var_order = re.findall(r'%([^%]+)%', line125)
print(f"Line 125 references {len(var_order)} variables")

# Concatenate
full = ''
for v in var_order:
    if v in variables:
        full += variables[v]

print(f"Concatenated length: {len(full)} characters")

# Remove separator
full_clean = full.replace('djlrttmeqqkr', '')
print(f"After removing separators: {len(full_clean)} characters")

# Show structure
print("\n" + "="*80)
print("FULL COMMAND STRUCTURE:")
print("="*80)
print(full_clean[:800])
print("="*80)

# Find the $s=' pattern
pattern = r'\$s=\'([^\']+)\''
match = re.search(pattern, full_clean)

if match:
    print("\nFound $s variable!")
    base64_payload = match.group(1)
    print(f"Base64 payload length: {len(base64_payload)}")
    print(f"First 100 chars: {base64_payload[:100]}")
    print(f"Last 100 chars: ...{base64_payload[-100:]}")

    # Save the extracted base64
    with open('extracted_base64.txt', 'w') as f:
        f.write(base64_payload)
    print("\nSaved base64 payload to extracted_base64.txt")

    # Now decode it
    import base64

    print("\nDecoding base64...")
    # Add padding if needed
    padding = len(base64_payload) % 4
    if padding:
        base64_payload += '=' * (4 - padding)
        print(f"Added {4 - padding} padding characters")

    try:
        decoded_bytes = base64.b64decode(base64_payload)
        print(f"Decoded to {len(decoded_bytes)} bytes")

        # Save binary
        with open('extracted_payload.bin', 'wb') as f:
            f.write(decoded_bytes)
        print("Saved to extracted_payload.bin")

        # Try UTF-16 LE
        print("\nDecoding as UTF-16 LE...")
        try:
            decoded_text = decoded_bytes.decode('utf-16-le')
            print(f"Success! Decoded to {len(decoded_text)} characters")

            # Save
            with open('extracted_payload.ps1', 'w', encoding='utf-8') as f:
                f.write(decoded_text)
            print("Saved to extracted_payload.ps1")

            # Search for flag
            flags = re.findall(r'HTB\{[^}]+\}', decoded_text)
            if flags:
                print("\n" + "="*80)
                print("FLAG FOUND:")
                print("="*80)
                for flag in flags:
                    print(f"  {flag}")
                print("="*80)
            else:
                print("\nNo HTB{...} pattern found in decoded text")

                # Check for TB{ (missing H)
                if 'TB{' in decoded_text:
                    print("Found 'TB{' pattern")
                    for m in re.finditer(r'.{0,20}TB\{[^}]+\}.{0,20}', decoded_text):
                        print(f"  Context: {repr(m.group())}")

            # Show first 500 chars
            print("\n" + "="*80)
            print("DECODED POWERSHELL (first 500 chars):")
            print("="*80)
            print(decoded_text[:500])
            print("="*80)

        except UnicodeDecodeError as e:
            print(f"UTF-16 LE decode error: {e}")
            print("\nTrying with error handling...")
            decoded_text = decoded_bytes.decode('utf-16-le', errors='replace')
            with open('extracted_payload_errors.ps1', 'w', encoding='utf-8') as f:
                f.write(decoded_text)
            print("Saved with errors to extracted_payload_errors.ps1")
            print("\nFirst 500 chars with replacement characters:")
            print(decoded_text[:500])

    except Exception as e:
        print(f"Error decoding base64: {e}")
        import traceback
        traceback.print_exc()
else:
    print("\nCould not find $s=' pattern in command")
    print("Searching for alternate patterns...")

    # Maybe it uses double quotes?
    pattern2 = r'\$s="([^"]+)"'
    match2 = re.search(pattern2, full_clean)
    if match2:
        print("Found $s with double quotes!")
    else:
        print("No $s pattern found at all")
