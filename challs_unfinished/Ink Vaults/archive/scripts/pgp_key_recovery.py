#!/usr/bin/env python3
"""
Comprehensive PGP Key Recovery from Scroll Images
Based on "clapper-less bell" hint analysis

This script attempts to:
1. Extract all possible bit plane combinations from scrolls
2. Repair corrupted PGP key data
3. Parse OpenPGP packet structures
4. Find authentication tokens in recovered keys
"""

import sys
from PIL import Image
import numpy as np
import re
import struct

# OpenPGP packet types that might contain auth tokens or keys
PGP_PACKET_TYPES = {
    0x02: "Signature",
    0x05: "Secret Key",
    0x06: "Public Key",
    0x07: "Secret Subkey",
    0x0C: "Trust",
    0x0D: "User ID",
    0x0E: "Public Subkey",
    0x7F: "User Attribute"
}

def extract_all_bit_planes(image_path, scroll_num):
    """Extract ALL bit plane combinations from a scroll image"""
    try:
        img = Image.open(image_path)
        pixels = np.array(img)
        height, width, channels = pixels.shape

        print(f"\n=== Processing {image_path} ({width}x{height}x{channels}) ===")

        extractions = {}

        # Try all bit positions (1-8)
        for bit_pos in range(1, 9):
            bit_idx = bit_pos - 1

            # Try all color channels and combinations
            for channel in ['r', 'g', 'b', 'rgb']:
                channel_info = channel if channel != 'rgb' else 'all'
                print(f"  Testing b{bit_pos},{channel_info}...")

                data = bytearray()

                if channel == 'rgb':
                    # Extract from all channels
                    for y in range(height):
                        for x in range(width):
                            for c in range(3):
                                pixel_val = int(pixels[y, x, c])
                                bit = (pixel_val >> bit_idx) & 1
                                data.append(bit)
                else:
                    # Extract from specific channel
                    channel_idx = {'r': 0, 'g': 1, 'b': 2}[channel]
                    for y in range(height):
                        for x in range(width):
                            pixel_val = int(pixels[y, x, channel_idx])
                            bit = (pixel_val >> bit_idx) & 1
                            data.append(bit)

                key = f"b{bit_pos}_{channel}_msb"
                extractions[key] = bytes(data)

                # Quick heuristic: check if this looks like structured data
                if len(data) > 100:
                    # Check for ASCII text
                    try:
                        ascii_preview = data[:200].decode('ascii', errors='ignore')
                        printable = sum(1 for c in ascii_preview if c.isprintable() or c.isspace())
                        if printable > len(ascii_preview) * 0.7:
                            print(f"    ✓ Looks like ASCII: {ascii_preview[:80]}...")
                    except:
                        pass

                    # Check for OpenPGP magic bytes (0x99, 0x95, 0x88, 0xB0)
                    if data.find(b'\x99') != -1 or data.find(b'\x95') != -1 or \
                       data.find(b'\x88') != -1 or data.find(b'\xb0') != -1:
                        print(f"    ✓ Found PGP magic bytes")

                    # Check for ASCII-armored PGP blocks
                    if b'-----BEGIN' in data or b'-----END' in data:
                        print(f"    ✓ Found ASCII-armored PGP block")

        return extractions

    except Exception as e:
        print(f"Error processing {image_path}: {e}")
        return {}

def detect_pgp_packets(data):
    """Detect OpenPGP packet structures in binary data"""
    packets = []

    # Look for OpenPGP packet markers
    markers = [b'\x98', b'\x99', b'\x95', b'\x88', b'\x89', b'\x8A', b'\x8B']

    for marker in markers:
        pos = 0
        while True:
            pos = data.find(marker, pos)
            if pos == -1:
                break

            if pos + 5 < len(data):
                # Try to parse packet header
                try:
                    packet_type = (data[pos] & 0x3F)  # Lower 6 bits
                    length_type = (data[pos] & 0x3)   # Lower 2 bits (for old format)

                    if packet_type in PGP_PACKET_TYPES:
                        print(f"    Found PGP packet at offset {pos}: {PGP_PACKET_TYPES[packet_type]}")
                        packets.append({
                            'pos': pos,
                            'type': packet_type,
                            'type_name': PGP_PACKET_TYPES[packet_type]
                        })
                except:
                    pass

            pos += 1

    return packets

def repair_gpg_packets(data):
    """Attempt to repair corrupted OpenPGP packets"""
    # Look for partial packets that might be split across files
    repairs = []

    # Search for partial packet headers
    pattern = re.compile(b'[\x88-\x9F]')
    for match in pattern.finditer(data):
        offset = match.start()
        if offset + 10 < len(data):
            # Try to reconstruct from this point
            candidate = data[offset:offset+1000]
            packets = detect_pgp_packets(candidate)
            if packets:
                repairs.append({
                    'offset': offset,
                    'packets': packets,
                    'data': candidate
                })

    return repairs

def search_for_auth_token(data):
    """Search for authentication tokens, passwords, or secrets in data"""
    secrets = []

    # Look for common token patterns
    patterns = {
        'jwt': rb'eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+',
        'bearer': rb'Bearer\s+[A-Za-z0-9-_]+',
        'auth': rb'auth[\s:=]+[A-Za-z0-9]+',
        'token': rb'token[\s:=]+[A-Za-z0-9]+',
        'password': rb'password[\s:=]+[A-Za-z0-9]+',
        'key': rb'[0-9a-f]{32,}',  # Hex keys
        'alphanumeric': rb'[A-Za-z0-9]{20,}',  # Long alphanumeric strings
    }

    for name, pattern in patterns.items():
        matches = re.finditer(pattern, data, re.IGNORECASE)
        for match in matches:
            token = match.group(0)
            if len(token) > 10:  # Not too short
                secrets.append({
                    'type': name,
                    'token': token.decode('utf-8', errors='ignore')
                })

    return secrets

def main():
    print("=== PGP Key Recovery from Ink Vaults Scrolls ===")
    print("Extracting all possible bit planes from scroll images...")
    print("Based on 'clapper-less bell' hint and challenge patterns.\n")

    # Process each scroll
    all_extractions = {}
    for scroll_num in range(1, 8):
        image_path = f"scroll_{scroll_num}.png"
        extractions = extract_all_bit_planes(image_path, scroll_num)
        all_extractions[scroll_num] = extractions

    print("\n" + "="*60)
    print("=== Analyzing Extracted Data ===")
    print("="*60)

    # Analyze each extraction
    for scroll_num, extractions in all_extractions.items():
        print(f"\nScroll {scroll_num}:")
        for key, data in extractions.items():
            print(f"  {key}: {len(data)} bytes")

            # Save to file for later analysis
            output_file = f"extracted_data/scroll_{scroll_num}_{key}_all.bin"
            with open(output_file, 'wb') as f:
                f.write(data)

            # Detect PGP packets
            packets = detect_pgp_packets(data)
            if packets:
                print(f"    → Found {len(packets)} PGP packets")

            # Search for secrets
            secrets = search_for_auth_token(data)
            if secrets:
                print(f"    → Found {len(secrets)} potential secrets:")
                for secret in secrets[:5]:  # Show first 5
                    print(f"      - {secret['type']}: {secret['token'][:50]}...")

            # Try ASCII armor detection
            if len(data) > 100:
                try:
                    text = data.decode('utf-8', errors='ignore')
                    if '-----BEGIN' in text or ('PGP' in text and 'KEY' in text):
                        # Find PGP block
                        start = text.find('-----BEGIN')
                        if start != -1:
                            end = text.find('-----END', start)
                            if end != -1:
                                block = text[start:end+50]
                                print(f"\n    === ASCII ARMORED PGP BLOCK DETECTED ===")
                                print(f"\n{block[:500]}...")
                                print(f"\n    === END PGP BLOCK ===\n")
                except:
                    pass

    print("\n" + "="*60)
    print("=== Cross-File Analysis ===")
    print("="*60)

    # Try to combine data from multiple scrolls (keys might be split)
    print("\nLooking for key fragments split across scrolls...")

    # Try stacking scrolls 1-7 data
    combined_data = bytearray()
    for scroll_num in range(1, 8):
        # Take just first 1000 bytes from each scroll's b3_rgb extraction
        key = 'b3_rgb_msb'
        if key in all_extractions[scroll_num]:
            data = all_extractions[scroll_num][key]
            combined_data.extend(data[:1000])

    print(f"Combined data size: {len(combined_data)} bytes")

    # Search combined data for secrets
    combined_secrets = search_for_auth_token(bytes(combined_data))
    if combined_secrets:
        print(f"Found {len(combined_secrets)} secrets in combined data:")
        for secret in combined_secrets[:10]:
            print(f"  - {secret['type']}: {secret['token']}")

    # Try bitwise OR/XOR combinations (data might be obfuscated)
    print("\n=== Testing Obfuscation Patterns ===")

    # Try XOR with 0xFF (common obfuscation)
    xored_data = bytes(b ^ 0xFF for b in combined_data[:1000])
    xor_secrets = search_for_auth_token(xored_data)
    if xor_secrets:
        print("Found secrets in XOR'd data:")
        for secret in xor_secrets[:5]:
            print(f"  - {secret['type']}: {secret['token']}")

    print("\n" + "="*60)
    print("=== Summary ===")
    print("="*60)
    print("All bit planes extracted and saved to extracted_data/")
    print("Check the output above for PGP blocks and secrets.")
    print("\nRecommended next steps:")
    print("1. Manually examine large extracted files for PGP armored blocks")
    print("2. Try importing detected keys with 'gpg --import'")
    print("3. Search recovered data for guardian authentication token")
    print("4. Try different bitwise operations if data is obfuscated")

if __name__ == "__main__":
    main()
