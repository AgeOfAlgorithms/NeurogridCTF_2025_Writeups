# MirrorPort - New Discoveries

## Date: 2025-11-22

## Critical Discoveries

### 1. IMG-Based XSS Bypass for Strict CSP ✅

**Discovery**: IMG tags execute in cached /sandbox pages despite strict CSP that blocks inline scripts.

**How it works**:
1. Create listing with XSS in `seller_name` field
2. Use SSRF to mirror the `/sandbox/<id>` page containing the XSS
3. The mirrored page is cached with strict CSP (`script-src 'none'`)
4. **BUT** CSP allows `img-src 'self'`, so IMG tags can make requests
5. When cached page is visited, IMG tags load and make HTTP requests

**Proof of Concept**:
- Created listing #367 with IMG-based XSS
- Mirrored to cache: `cache_368_edb715870925f0d68200852aea2b98e5`
- When visited with Playwright, IMG tags successfully made requests to `/api/listings` and `/sandbox/365`

**Code**: [test_img_based_xss.py](test_img_based_xss.py)

### 2. Request Mirroring Works ✅

**Discovery**: SSRF can successfully fetch and cache internal endpoints including `/sandbox` pages.

**Tested URLs**:
- ✅ `http://127.0.0.1:3000/api/listings` - Successfully cached
- ✅ `http://127.0.0.1:3000/sandbox/<id>` - Successfully cached with XSS intact
- ❌ `http://127.0.0.1:9001/RPC2` (supervisord) - Not accessible or no response
- ❌ `dict://127.0.0.1:6379/INFO` (Redis) - Not cached (protocol not supported by curl)

### 3. file:// Redirect Bypass FAILS ❌

**Attempted**: HTTP redirect to `file://` to bypass protocol filter

**Result**: FAILED - `Protocol "file" not supported or disabled in libcurl`

Curl output: `curl: (1) Protocol "file" not supported or disabled in libcurl`

This means even if we redirect from http:// to file://, curl won't follow it.

## Architecture Understanding

### Services
- **Nginx** (port 80): Reverse proxy, serves React SPA
- **Flask** (port 3000): Backend API (runs as `flaskuser`)
- **Redis** (port 6379): Session storage (runs as `redisuser`)
- **Celery Worker**: Async URL fetching (runs as `celeryuser`)
- **Supervisord** (port 9001): Process manager

### Key Files & Permissions
- `/usr/local/bin/read_flag` - SUID 4755, can read `/root/flag.txt`
- `/root/flag.txt` - chmod 600, only readable by root or via read_flag
- `/logs` - chmod 644, owned by nginx, contains Nginx access logs in JSON format
- `/app/cache` - chmod 755, owned by celeryuser, stores cached SSRF content

### URL Filtering Logic
In `tasks.py` line 29:
```python
if url.startswith(('gopher://', 'file://', "-K", "-k")):
    return {'error': 'Skipped URL', 'success': False}
```

Only blocks: `gopher://`, `file://`, and curl flags `-K`, `-k`

### Curl Command Construction
```python
curl_cmd = f"{curl_binary} {shlex.join(curl_cmd)}"
result = subprocess.run(curl_cmd, capture_output=True, shell=True, text=True, timeout=35)
```

- Uses `shlex.join()` to escape arguments (prevents basic command injection)
- Executes with `shell=True` (but shlex.join provides protection)
- Uses `-L` flag (follows redirects)

## Exploit Chain So Far

1. ✅ **XSS in seller_name** → Executes at `/sandbox/<id>`
2. ✅ **SSRF mirrors /sandbox** → Caches XSS payload
3. ✅ **IMG tags bypass CSP** → Can make HTTP requests from cached page
4. ❓ **Missing Link** → How to execute `/usr/local/bin/read_flag`?

## Attempted Exploits (Failed)

1. ❌ Direct file:// access - Blocked by filter
2. ❌ HTTP redirect to file:// - Protocol disabled in libcurl
3. ❌ dict:// protocol to Redis - Not supported/cached
4. ❌ Supervisord XML-RPC access - Not accessible
5. ❌ Path traversal to /logs - Normalized by Flask
6. ❌ SSTI in various fields - No template injection found
7. ❌ URL filter bypass with uppercase FILE:// - Still blocked
8. ❌ Curl command injection via special chars - Prevented by shlex.join()

## Open Questions

### Q1: Is there a bot?
User hint: "read_flag would be executed somehow by you or another bot"

**No bot code found** in the challenge files. Searched for: selenium, puppeteer, playwright, headless, browser, visit, crawl

**Possibilities**:
- Bot exists but code not in download
- "Bot" refers to Celery worker
- "You" means I need to trigger execution via exploit chain
- Bot visits certain endpoints automatically

### Q2: How is read_flag meant to be executed?
No code found that executes read_flag. Possibilities:
- Hidden endpoint not discovered
- Command injection through curl (but shlex.join prevents this)
- File upload processing (haven't fully explored)
- Some curl feature/vulnerability
- Chaining SSRF + XSS in unexpected way

### Q3: What is the significance of /logs?
- Nginx writes access logs to /logs in JSON format with request bodies
- File is chmod 644, readable by all
- Could inject payloads into logs
- Cannot read /logs directly via HTTP (falls through to React SPA)
- SSRF to /logs returns 404

## Next Steps to Investigate

1. **File Upload Functionality**
   - Examine `/api/upload/image` endpoint more carefully
   - Check if uploaded files are processed in any way
   - Test if uploads can trigger code execution

2. **Curl Advanced Features**
   - Research curl URL glob patterns
   - Test curl's handling of special URL formats
   - Check for curl-specific SSRF vulnerabilities

3. **Alternative SSRF Targets**
   - Internal services on other ports
   - Unix sockets
   - Cloud metadata endpoints (if running on AWS/GCP/Azure)

4. **XSS Chain Escalation**
   - Can IMG tags be chained to cause server-side effects?
   - Exploit timing/race conditions
   - Trigger some automated process

5. **Ask User for Hints**
   - Is there a bot that visits pages?
   - Am I on the right track with IMG-based XSS?
   - What aspect of "MirrorPort" haven't I exploited yet?

## Tools Created

- `test_xss_execution.py` - Initial XSS test
- `test_mirror_sandbox.py` - Mirror /sandbox pages
- `test_img_based_xss.py` - IMG-based CSP bypass
- `test_supervisord_access.py` - SSRF to supervisord
- `test_internal_flask.py` - SSRF to internal Flask
- `test_dict_protocol.py` - dict:// protocol test
- `test_logs_ssrf.py` - Attempt to read /logs
- `test_redirect_bypass.py` - Redirect to file:// concept
- `test_url_injection.py` - Test shlex.join behavior

## Success Rate
This challenge has only been solved by 2 out of 148 teams (1.35%), indicating it requires a very specific, non-obvious exploitation technique that I haven't discovered yet.
