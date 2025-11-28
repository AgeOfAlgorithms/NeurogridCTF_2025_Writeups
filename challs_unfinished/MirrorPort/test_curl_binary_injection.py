#!/usr/bin/env python3
"""
Test script to verify curl_binary parameter injection in Celery task.

This script tests the hypothesis that we can inject the curl_binary parameter
by manipulating how Celery deserializes task arguments.

Author: CTF Solver
Purpose: Test parameter injection in Celery task
Date: 2025-11-23
"""

import sys
import json
import requests
import time

# Note: This would need to be run against the live instance
# For now, it's a proof-of-concept showing the attack vector

def test_theory():
    """
    Our theory: If we can somehow pass additional arguments to the Celery task,
    we could set curl_binary='/usr/local/bin/read_flag' which would execute
    the SUID binary instead of curl, dumping the flag to stdout which gets cached.
    """

    # The Celery task signature:
    # fetch_url(url: str, listing_id, curl_binary='/usr/bin/curl')

    # If Celery's message format allows variable arguments,
    # we might inject a third argument

    print("=== Curl Binary Injection Theory ===")
    print()
    print("Target: tasks.py::fetch_url() function")
    print("Parameter: curl_binary (default='/usr/bin/curl')")
    print("Goal: Inject curl_binary='/usr/local/bin/read_flag'")
    print()
    print("If successful, read_flag would execute and output:")
    print("  Flag: HTB{...}")
    print()
    print("This output would be cached by Celery and accessible via /cache/")
    print()
    print("=== Attack Vectors to Test ===")
    print()
    print("1. If Redis is accessible, try to directly inject task with extra args")
    print("2. If Celery has a message format vulnerability, craft malicious message")
    print("3. If listing ID can be confused with arguments, exploit that")
    print()
    print("=== How to Test ===")
    print()
    print("Would need to:")
    print("1. Access Redis at 127.0.0.1:6379")
    print("2. Craft Celery task message with 3 arguments instead of 2")
    print("3. Monitor /cache/ for output from read_flag")
    print()

if __name__ == '__main__':
    test_theory()
