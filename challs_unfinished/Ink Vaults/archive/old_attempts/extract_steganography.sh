#!/bin/bash

# Extract steganographic data from scroll images
# Based on findings in ATTEMPT.md

echo "=== Ink Vaults Steganography Extraction ==="
echo

# Create output directory
mkdir -p extracted_data

# Tools to try
# 1. zsteg (for PNG files)
# 2. steghide
# 3. outguess
# 4. binwalk

echo "Scanning scroll images for hidden data..."
echo

for i in {1..7}; do
    echo "=== Processing scroll_$i.png ==="

    # Use zsteg to find hidden data
    echo "Running zsteg on scroll_$i.png..."
    zsteg scroll_$i.png > extracted_data/scroll_${i}_zsteg.txt 2>&1 || echo "zsteg not available or found nothing"

    # Use binwalk to extract embedded files
    echo "Running binwalk on scroll_$i.png..."
    binwalk -e scroll_$i.png -C extracted_data/scroll_${i}_binwalk 2>&1 | head -20

    # Try steghide (no password)
    echo "Attempting steghide extraction (no password)..."
    steghide extract -sf scroll_$i.png -xf extracted_data/scroll_${i}_steghide.bin -p "" 2>&1 || echo "steghide found nothing"

    echo
done

echo "=== Extraction complete ==="
echo "Check extracted_data/ directory for results"
