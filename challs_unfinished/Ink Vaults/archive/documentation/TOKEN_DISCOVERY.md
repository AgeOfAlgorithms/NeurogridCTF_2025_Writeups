# Admin Token Discovery

## Token Location

The admin JWT token was found embedded in the client-side JavaScript file:
**File:** `js_analysis/archivist_page.js`

## How It Was Found

```bash
grep -o "eyJ[A-Za-z0-9._-]*" js_analysis/archivist_page.js
```

This revealed multiple JWT tokens, including:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwidXNlcm5hbWUiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImVtYWlsIjoidGVzdEB0ZXN0LmNvbSIsImlhdCI6MTc2MzY3MzU3OCwiZXhwIjoxNzYzNjc3MTc4LCJqdGkiOiJmb3JnZWQtYWRtaW4tdG9rZW4tMDAxIn0.8BP6OaQSuOOKO0HMv4wAhwR8_22kfL7f6FKzVISxYgk
```

## Token Decoded

**Header:**
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**Payload:**
```json
{
  "sub": "1",
  "username": "admin",
  "role": "admin",
  "email": "test@test.com",
  "iat": 1763673578,
  "exp": 1763677178,
  "jti": "forged-admin-token-001"
}
```

## Why This Works

The admin token bypasses the `onBeforeCall` hook's authentication check because it has `"role": "admin"`, which likely skips the "great unwriting" authentication requirement for the `guardian_query_sql` tool.

This is a classic example of client-side secret leakage - hardcoded credentials in JavaScript that should have been removed in production.
