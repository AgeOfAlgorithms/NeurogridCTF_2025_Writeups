# MirrorPort Challenge - Current Blockers

**Time:** 2025-11-22

## Problem Summary
- Flag location: `/root/flag.txt` (chmod 600, only readable by root)
- Accessible via: `/usr/local/bin/read_flag` (SUID binary, chmod 4755)
- Challenge: No discovered method to execute `read_flag` or access its output

## What We Know Works
✅ **XSS Vulnerability**: seller_name field in /sandbox/<id> with `'unsafe-inline'` CSP
✅ **SSRF Capability**: Celery fetches HTTP/HTTPS URLs via curl with `-L` flag
✅ **Request Mirroring**: Confirmed ability to cache SSRF-fetched content
✅ **Nginx Logging**: All requests logged to `/logs` (644 permissions) in JSON format with request bodies

## Attempted Approaches (All Failed)

### 1. Direct File Access via curl
- ❌ `file:///logs` - Blocked by URL filter in tasks.py:29
- ❌ `FILE:///logs` (uppercase) - Blocked by filter_http_urls() in listing.py:76 (requires http/https)
- ❌ URL encoding (`file%3A%2F%2F%2Flogs`) - Still doesn't start with http://
- ❌ Punctuation prefix (`:::file:///logs`) - Doesn't start with http:// after stripping punctuation

### 2. HTTP Redirect Approaches
- ❌ webhook.site redirect to file:// - Blocked by curl's CVE-2009-0037 protection (since curl 7.19.4)
- ❌ Double redirects (HTTP -> HTTP -> file://) - Still blocked by curl's protection
- ❌ Custom redirect servers - Modern curl blocks file:// redirects by default

### 3. SSRF to Internal Endpoints
- ❌ `http://127.0.0.1:3000/logs` - Returns 404 (Flask doesn't serve /logs)
- ❌ Path traversal (`http://127.0.0.1:3000/../logs`) - Returns 404
- ❌ nginx direct access to /logs - No route configured

### 4. Code Injection / Exploitation
- ❌ Command injection in curl - Protected by `shlex.join()`
- ❌ SSTI in templates - Templates render literally, no evaluation
- ❌ Redis exploitation via SSRF - No useful endpoints found
- ❌ Nginx alias traversal - Properly configured with trailing slashes

### 5. Other Attempts
- ❌ Accessing /logs via HTTP on any port - No endpoint serves it
- ❌ Race conditions with temp files - No exploitable window found
- ❌ Environment/config file access - Inaccessible
- ❌ Port scanning - Only ports 80 (nginx) and 3000 (Flask) accessible

## Key Constraints

### URL Filtering (listing.py:76)
```python
for url in urls[:]:
    if url.strip(string.punctuation).startswith(('http://', 'https://')):
        filtered_urls.append(url)  # Only http/https URLs pass
```

### Celery URL Filter (tasks.py:29)
```python
if url.startswith(('gopher://', 'file://', "-K", "-k")):
    return {'error': 'Skipped URL', 'success': False}
```

### Curl Redirect Protection
- Modern curl (7.19.4+) blocks redirects to file://, gopher://, etc.
- Default `CURLOPT_REDIR_PROTOCOLS` allows only HTTP, HTTPS, FTP, FTPS

## Missing Link
Despite having:
1. XSS that can execute JavaScript (with `connect-src 'self'` CSP)
2. SSRF that can fetch internal HTTP endpoints
3. Request mirroring capability
4. World-readable /logs file with all request data

**We cannot:**
- Execute `/usr/local/bin/read_flag`
- Read `/root/flag.txt`
- Access `/logs` file content
- Find any other path to the flag

## Questions / Theories

1. **Is there a subtle vulnerability in the code we missed?**
   - Reviewed all Python files, nginx.conf, Dockerfile
   - No obvious backdoors or misconfigurations found

2. **Is the flag already in cached data somewhere?**
   - Checked existing listings and backend assets
   - Nothing suspicious found

3. **Does "MirrorPort" hint at a specific technique?**
   - Port mirroring? Data mirroring? Port as in harbor?
   - No clear connection to a known exploit

4. **Is there a curl vulnerability we haven't exploited?**
   - Researched 2023-2024 CVEs
   - No applicable local file read vulnerabilities found

5. **Are we supposed to chain XSS + SSRF differently?**
   - XSS can only connect to same-origin (`connect-src 'self'`)
   - No endpoint found that executes read_flag or returns flag content

## User's Note
- Original hint about "HTTP redirect services like webhook.site" was clarified as "just a guess in the dark"
- This suggests redirect-based approaches may not be the solution

## Challenge Statistics
- **Difficulty**: Easy (rated)
- **Solves**: 2 out of 148 teams
- **Reality**: This is an extremely difficult challenge despite the "Easy" rating

## Request for Guidance
I've exhaustively explored the application code and tested numerous attack vectors. At this point, I would benefit from a hint about:
1. What aspect of the application should I focus on?
2. Am I on the right track with trying to access /logs or execute read_flag?
3. Is there a specific technique or vulnerability type I should research?
