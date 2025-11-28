#!/usr/bin/env python3
"""
Author: Claude
Purpose: Extract C2 communication on port 8484
Created: 2025-11-20
Expected result: Extract and decode C2 traffic
Updated: Initial version
"""

from scapy.all import rdpcap, TCP, IP, Raw
import binascii

packets = rdpcap('network.pcapng')

print("=== Extracting C2 Traffic (Port 8484) ===\n")

# Filter for port 8484
c2_packets = []
for pkt in packets:
    if TCP in pkt and (pkt[TCP].sport == 8484 or pkt[TCP].dport == 8484):
        c2_packets.append(pkt)

print(f"Found {len(c2_packets)} packets on port 8484\n")

# Separate by direction
client_to_server = []
server_to_client = []

for pkt in c2_packets:
    if Raw in pkt:
        data = bytes(pkt[Raw].load)
        if pkt[TCP].dport == 8484:
            client_to_server.append(data)
        else:
            server_to_client.append(data)

print(f"Client -> Server: {len(client_to_server)} packets")
print(f"Server -> Client: {len(server_to_client)} packets")

# Save all data to files
with open('c2_client_to_server.bin', 'wb') as f:
    for data in client_to_server:
        f.write(data)
print(f"\nSaved client data to c2_client_to_server.bin")

with open('c2_server_to_client.bin', 'wb') as f:
    for data in server_to_client:
        f.write(data)
print(f"Saved server data to c2_server_to_client.bin")

# Show first few packets
print("\n=== First few Client->Server packets ===")
for i, data in enumerate(client_to_server[:5]):
    print(f"\nPacket {i+1} ({len(data)} bytes):")
    print(f"Hex: {binascii.hexlify(data[:64]).decode()}")
    # Try to see if there's any ASCII
    try:
        ascii_data = data.decode('ascii', errors='ignore')
        if ascii_data.strip():
            print(f"ASCII: {ascii_data[:100]}")
    except:
        pass

print("\n=== First few Server->Client packets ===")
for i, data in enumerate(server_to_client[:5]):
    print(f"\nPacket {i+1} ({len(data)} bytes):")
    print(f"Hex: {binascii.hexlify(data[:64]).decode()}")
    try:
        ascii_data = data.decode('ascii', errors='ignore')
        if ascii_data.strip():
            print(f"ASCII: {ascii_data[:100]}")
    except:
        pass
