#!/usr/bin/env python3
"""
Decrypt C2 traffic once the key is found

Usage:
1. Edit the KEY and NONCE variables below
2. Run: python3 decrypt_with_key.py
"""

from Crypto.Cipher import ChaCha20
from scapy.all import rdpcap, TCP, Raw

# ============================================================================
# FILL THESE IN WITH VALUES FROM GHIDRA:
# ============================================================================

# The 32-byte ChaCha20 key (64 hex characters)
KEY = bytes.fromhex(
    "REPLACE_WITH_32_BYTE_KEY_HERE"  # 64 hex chars
    # Example: "7f65e66d7b992f00e39bd0933f6ed9732c99bf22e061c0fbf46af3aeb1c52bc0"
)

# The nonce (12 bytes for ChaCha20-IETF, or 8 bytes for original)
NONCE = bytes.fromhex(
    "000000000000000000000000"  # 12 bytes (24 hex chars)
    # Or try 8 bytes: "0000000000000000" (16 hex chars)
)

# Nonce derivation pattern (if not fixed)
NONCE_PATTERN = "fixed"  # Options: "fixed", "tcp_seq", "packet_num", "custom"

# ============================================================================

def decrypt_packet(data, key, nonce):
    """Decrypt a single packet with ChaCha20"""
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return cipher.decrypt(data)

def main():
    print("="*70)
    print("ChaCha20 C2 Traffic Decryptor")
    print("="*70)
    print()

    # Validate inputs
    if len(KEY) != 32:
        print(f"❌ ERROR: Key must be 32 bytes, got {len(KEY)} bytes")
        print("   Make sure KEY is 64 hex characters (32 bytes)")
        return

    if len(NONCE) not in [8, 12]:
        print(f"❌ ERROR: Nonce must be 8 or 12 bytes, got {len(NONCE)} bytes")
        print("   Make sure NONCE is 16 (8-byte) or 24 (12-byte) hex characters")
        return

    print(f"Key:   {KEY.hex()}")
    print(f"Nonce: {NONCE.hex()} ({len(NONCE)} bytes)")
    print(f"Pattern: {NONCE_PATTERN}")
    print()

    # Load PCAP
    print("Loading network.pcapng...")
    packets = rdpcap('network.pcapng')

    # Extract server packets
    server_packets = []
    for pkt in packets:
        if TCP in pkt and Raw in pkt:
            if pkt[TCP].sport == 8484:  # From server
                data = bytes(pkt[Raw].load)
                tcp_seq = pkt[TCP].seq
                server_packets.append((data, tcp_seq))

    print(f"Found {len(server_packets)} server packets")
    print()
    print("="*70)
    print("DECRYPTING...")
    print("="*70)
    print()

    flag_found = False

    for i, (enc_data, tcp_seq) in enumerate(server_packets):
        # Derive nonce based on pattern
        if NONCE_PATTERN == "fixed":
            nonce = NONCE
        elif NONCE_PATTERN == "tcp_seq":
            nonce = tcp_seq.to_bytes(len(NONCE), 'little')
        elif NONCE_PATTERN == "packet_num":
            nonce = i.to_bytes(len(NONCE), 'little')
        else:
            nonce = NONCE  # Custom - modify as needed

        # Decrypt
        try:
            plaintext = decrypt_packet(enc_data, KEY, nonce)

            print(f"Packet {i} (TCP seq: {tcp_seq}):")
            print(f"  Encrypted: {len(enc_data)} bytes")
            print(f"  Decrypted first 100 bytes:")
            print(f"    Hex: {plaintext[:100].hex()}")

            # Try to print as ASCII
            try:
                ascii_text = plaintext.decode('ascii', errors='replace')
                if any(c.isprintable() for c in ascii_text[:100]):
                    print(f"    ASCII: {ascii_text[:100]}")
            except:
                pass

            # Check for flag
            if b'HTB{' in plaintext:
                print()
                print("="*70)
                print("🚩🚩🚩 FLAG FOUND! 🚩🚩🚩")
                print("="*70)

                # Extract flag
                flag_start = plaintext.find(b'HTB{')
                flag_end = plaintext.find(b'}', flag_start) + 1
                flag = plaintext[flag_start:flag_end].decode('ascii', errors='replace')

                print(f"\nFLAG: {flag}")
                print()
                print("Full decrypted packet:")
                print(plaintext)
                print()
                print("="*70)

                flag_found = True
                break

            print()

        except Exception as e:
            print(f"  ❌ Decryption failed: {e}")
            print()

    if not flag_found:
        print()
        print("="*70)
        print("⚠️  Decryption completed but no flag found")
        print("="*70)
        print()
        print("Possible issues:")
        print("  1. Wrong key - verify the 32 bytes from Ghidra")
        print("  2. Wrong nonce - try different nonce patterns")
        print("  3. Nonce changes per packet - set NONCE_PATTERN accordingly")
        print()
        print("If length fields decrypt correctly but data is gibberish:")
        print("  - The nonce might be packet-specific")
        print("  - Try NONCE_PATTERN = 'packet_num' or 'tcp_seq'")
        print()
    else:
        print()
        print("✅ Success! Flag captured!")

if __name__ == "__main__":
    main()
