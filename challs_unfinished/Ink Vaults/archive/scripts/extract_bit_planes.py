#!/usr/bin/env python3
"""
Extract data from specific bit planes in scroll images.
Based on patterns found in ATTEMPT.md:
- Scroll 1: b3,rgb,msb,xy (OpenPGP Secret Key) and b4,r,lsb,xy (Public Key)
- Scroll 2: b1,r,msb,xy (OpenPGP Secret Key)
- Scroll 6: b3,g,lsb,xy (OpenPGP Secret Key)
- Scroll 7: b2,b,msb,xy (OpenPGP Secret Key)
"""

import sys
from PIL import Image
import numpy as np

def extract_bit_plane(image_path, bit_position, color_channel, bit_order='msb', endian='xy'):
    """
    Extract a specific bit plane from an image.

    Args:
        image_path: Path to the image file
        bit_position: Which bit to extract (1=LSB, 8=MSB)
        color_channel: 'r', 'g', 'b', or 'rgb' for all channels
        bit_order: 'msb' or 'lsb' for bit significance
        endian: 'xy' for normal order
    """
    img = Image.open(image_path)
    pixels = np.array(img)

    # Convert bit position (1-8) to array index (0-7)
    # bit_position=1 means LSB, bit_position=8 means MSB
    bit_idx = bit_position - 1

    extracted_data = bytearray()

    if color_channel == 'rgb':
        # Extract from all channels
        for y in range(pixels.shape[0]):
            for x in range(pixels.shape[1]):
                # Extract bit from each color channel
                for c in range(3):  # R, G, B
                    pixel_val = pixels[y, x, c]
                    bit = (pixel_val >> bit_idx) & 1
                    extracted_data.append(bit)
    else:
        # Extract from specific color channel
        channel_idx = {'r': 0, 'g': 1, 'b': 2}[color_channel]
        for y in range(pixels.shape[0]):
            for x in range(pixels.shape[1]):
                pixel_val = pixels[y, x, channel_idx]
                bit = (pixel_val >> bit_idx) & 1
                extracted_data.append(bit)

    return bytes(extracted_data)

def extract_and_save(scroll_num, bit_pos, channel, bit_order, output_suffix):
    """Extract bit plane and save to file"""
    image_path = f"scroll_{scroll_num}.png"

    try:
        print(f"Extracting {bit_order}{bit_pos},{channel} from {image_path}...")
        data = extract_bit_plane(image_path, bit_pos, channel, bit_order)

        output_file = f"extracted_data/scroll_{scroll_num}_{output_suffix}.bin"
        with open(output_file, 'wb') as f:
            f.write(data)

        print(f"  Saved {len(data)} bytes to {output_file}")

        # Try to detect if this looks like ASCII text
        try:
            ascii_preview = data[:200].decode('ascii', errors='ignore')
            if len(ascii_preview.strip()) > 10:
                print(f"  ASCII preview: {ascii_preview[:100]}...")
        except:
            pass

        return data
    except Exception as e:
        print(f"  Error: {e}")
        return None

def main():
    import os
    os.makedirs('extracted_data', exist_ok=True)

    print("=== Extracting Bit Planes from Scroll Images ===\n")

    # Extract based on patterns from ATTEMPT.md
    extractions = [
        # Scroll 1: b3,rgb,msb,xy (Secret Key)
        (1, 3, 'rgb', 'msb', 'b3_rgb_msb'),
        # Scroll 1: b4,r,lsb,xy (Public Key)
        (1, 4, 'r', 'lsb', 'b4_r_lsb'),
        # Scroll 2: b1,r,msb,xy (Secret Key)
        (2, 1, 'r', 'msb', 'b1_r_msb'),
        # Scroll 6: b3,g,lsb,xy (Secret Key)
        (6, 3, 'g', 'lsb', 'b3_g_lsb'),
        # Scroll 7: b2,b,msb,xy (Secret Key - terminating stroke)
        (7, 2, 'b', 'msb', 'b2_b_msb'),
    ]

    for scroll_num, bit_pos, channel, bit_order, suffix in extractions:
        extract_and_save(scroll_num, bit_pos, channel, bit_order, suffix)
        print()

    print("=== Extraction complete ===")

if __name__ == "__main__":
    main()
