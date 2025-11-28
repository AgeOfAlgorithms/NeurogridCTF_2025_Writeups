#!/usr/bin/env python3
"""Keep-alive script for HTB blockchain instance"""
from web3 import Web3
import time

RPC_URL = "http://154.57.164.76:30516/api/c5021f6e-c6d9-4aaf-bcf8-06b1f833d064"

w3 = Web3(Web3.HTTPProvider(RPC_URL))

print(f"[*] Keep-alive for instance: ...{RPC_URL[-12:]}", flush=True)
print(f"[*] Press Ctrl+C to stop", flush=True)

while True:
    try:
        block = w3.eth.block_number
        timestamp = time.strftime('%H:%M:%S')
        print(f"[{timestamp}] Block: {block}", flush=True, end='\r')
    except Exception as e:
        print(f"\n[!] Error: {e}", flush=True)
    time.sleep(60)
