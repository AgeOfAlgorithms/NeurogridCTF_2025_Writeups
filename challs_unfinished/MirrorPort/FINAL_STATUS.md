# MirrorPort - Final Status

## Challenge Remains UNSOLVED

**Instance**: http://154.57.164.68:32728  
**Solve Rate**: 2/148 teams (1.35%)  
**Time Spent**: Multiple sessions

## What We Confirmed

### Vulnerabilities Found
1. **XSS** - seller_name field at /sandbox/<id> with 'unsafe-inline' CSP
2. **SSRF** - Celery URL fetching via curl with -L flag
3. **Request Mirroring** - Can cache /sandbox pages via SSRF

### Attack Surface Mapped
- All Flask endpoints documented (10 total)
- Internal port 80 (nginx) and 3000 (Flask) accessible via SSRF
- File structure and permissions confirmed
- User separation: nginx, flaskuser, celeryuser, redisuser

### What Doesn't Work
- gopher://, file://, dict://, ftp://, tftp://, ldap:// protocols (blocked or disabled)
- -K curl config flag (blocked in URL filter)
- Command injection via URL (protected by shlex.join())
- Path traversal to /logs (nginx routing issue)
- Direct access to supervisord (not exposed)
- Redis exploitation via SSRF (not HTTP protocol)

## The Core Problem

**Goal**: Execute `/usr/local/bin/read_flag` (SUID binary) to read `/root/flag.txt`

**Key Code** (tasks.py:28):
```python
def fetch_url(url: str, listing_id, curl_binary='/usr/bin/curl'):
    curl_cmd = f"{curl_binary} {shlex.join(curl_cmd)}"
    result = subprocess.run(curl_cmd, shell=True, ...)
```

The `curl_binary` parameter could execute read_flag, but:
- No API endpoint passes this parameter
- All calls use default `/usr/bin/curl`
- Cannot inject due to shlex.join() protection

## Missing Insight

With only 1.35% solve rate, the solution likely involves:
1. A curl feature/flag we haven't discovered
2. A way to write .curlrc config file via upload/cache
3. An undiscovered endpoint or service
4. A creative chaining of XSS + SSRF we haven't thought of
5. Exploiting curl's config file reading behavior

## Recommended Next Steps

1. Research curl obscure features and config behaviors
2. Investigate if we can write files to celeryuser's $HOME
3. Deep dive into Flask/Celery/Redis interaction
4. Review if there's a race condition in cache file creation
5. Check if image upload can be abused to write arbitrary files

## Documentation
- [COMPREHENSIVE_RECON.md](COMPREHENSIVE_RECON.md) - All endpoints, ports, and tests
- [FINDINGS.md](FINDINGS.md) - Technical vulnerability details
- [ATTEMPT.md](ATTEMPT.md) - All exploitation attempts
