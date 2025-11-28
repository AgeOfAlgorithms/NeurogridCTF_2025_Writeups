# MirrorPort - Next Steps (Instance Currently Down)

## Current Status

The challenge instance at `http://154.57.164.72:32443` is currently down (Connection Refused).

## Key Information Confirmed

### No Bot Exists
User confirmed there is **probably no bot** that visits pages automatically. This means:
- The IMG-based XSS bypass I discovered (while technically interesting) is likely NOT the solution path
- The exploit must be entirely server-side via SSRF

### Flag Location
- Flag file: `/root/flag.txt` (chmod 600, only readable by root)
- SUID binary: `/usr/local/bin/read_flag` (chmod 4755, can read the flag)
- Goal: Either read the flag directly OR execute read_flag to get it

### SSRF Capabilities Confirmed
- ✅ Can fetch internal Flask endpoints (tested: `/api/listings`)
- ✅ Can mirror /sandbox pages with XSS intact
- ✅ curl runs with `-L` flag (follows HTTP redirects)
- ❌ file:// protocol redirects BLOCKED (protocol disabled in libcurl)
- ❌ Path traversal in /cache endpoint doesn't work

## Attack Surface To Explore (When Instance Returns)

### 1. Alternative Curl Protocols
Test protocols that curl supports besides http/https:
- `ftp://` - FTP protocol
- `tftp://` - Trivial FTP
- `ldap://` - LDAP protocol
- `dict://` - Already tested, doesn't work
- `smtp://` - SMTP protocol
- Others from `curl --version` output

**Script**: `test_curl_protocols.py`

### 2. Supervisord XML-RPC Interface
Supervisord runs on port 9001 with XML-RPC interface. Can potentially:
- Read process logs (`supervisor.readProcessStdoutLog`)
- Start/stop processes
- Get process status

Test if accessible and exploitable.

**Script**: `test_supervisord_rpc.py`

### 3. Hidden Flask Endpoints
The Flask app might have debug or hidden endpoints that:
- Execute commands
- Read files
- Serve the flag directly

Test endpoints like:
- `/debug/*`
- `/admin/*`
- `/console` (Werkzeug debug console)
- `/_debug_toolbar/`
- Any other common Flask debug routes

### 4. Curl Special Features
Research and test:
- Curl URL globbing/patterns
- Curl config file injection (blocked by `-K` filter but worth understanding)
- Curl output redirection tricks
- Curl's handling of special characters in URLs

### 5. File Upload Exploitation
Haven't fully explored `/api/upload/image`:
- What processing happens on uploaded files?
- Can we upload malicious files that get executed?
- Can we overwrite cache files?
- Any TOCTOU (Time-of-check-time-of-use) vulnerabilities?

### 6. Redis Exploitation
Redis runs on port 6379. Possible attacks:
- Can SSRF access Redis directly? (Need proper protocol)
- Redis command injection through some vector?
- Reading session data that might contain flag?

### 7. Process/Service Interaction
Services running (from supervisord.conf):
- redis (port 6379, user: redisuser)
- celery (user: celeryuser) - executes our SSRF
- flask (port 3000, user: flaskuser)
- nginx (port 80, user: nginx)

Can we:
- Make one service interact with another in unexpected ways?
- Exploit inter-process communication?
- Access Unix sockets?

### 8. Timing/Race Conditions
- Race between file creation and serving?
- Multiple simultaneous requests causing unexpected behavior?
- Cache poisoning through timing?

### 9. Log File Exploitation
- `/logs` file (chmod 644, JSON format with request bodies)
- Can we inject into logs and read them back somehow?
- SSRF to fetch `/logs` returned 404 - but is there another way?

### 10. Curl Command Injection Research
Even though `shlex.join()` is used, research:
- Known shlex.join bypasses
- Shell=True exploitation techniques
- Curl-specific command injection vectors

## Theoretical Exploit Paths To Investigate

### Path A: Direct Flag Access
1. Find service/endpoint that can read `/root/flag.txt`
2. Use SSRF to access that service
3. Cache the response containing flag

### Path B: Execute read_flag
1. Find way to make curl or another service execute `/usr/local/bin/read_flag`
2. Capture the output
3. Exfiltrate via cache or other means

### Path C: Privilege Escalation
1. Find vulnerability in one of the services
2. Escalate to root privileges
3. Read flag directly

### Path D: Creative Curl Usage
1. Use curl in an unexpected way that allows file reading
2. Exploit some curl feature/vulnerability
3. Access flag through creative protocol/URL manipulation

## Questions To Research

1. **Does curl have any lesser-known protocols or features that allow local file access?**
   - Check curl documentation for all supported protocols
   - Research curl CVEs related to SSRF/file disclosure

2. **Can supervisord's XML-RPC interface be exploited to execute commands?**
   - Research supervisord security issues
   - Check if we can read process output that might contain flag

3. **Is there a Flask debug mode or console accessible?**
   - Test for Werkzeug debug console
   - Check for Flask development server artifacts

4. **What happens if we poison the cache with specific filenames?**
   - Can we overwrite existing files?
   - Can we create files with special names?

5. **Is there any way to make Flask/Celery/Redis execute read_flag?**
   - Code execution vulnerabilities in dependencies?
   - Configuration injection?

## When Instance Returns

Run these tests in order:
1. `test_curl_protocols.py` - Test alternative curl protocols
2. `test_supervisord_rpc.py` - Try to access supervisord
3. `test_access_binary.py` - Test various internal endpoints
4. Manual testing of Flask debug endpoints
5. Deep dive into file upload functionality
6. Research curl documentation for exploitation vectors

## Files Created For Testing

- `test_mirror_sandbox.py` - Mirrors /sandbox pages via SSRF
- `test_img_based_xss.py` - IMG-based CSP bypass (not useful without bot)
- `test_curl_protocols.py` - Test alternative curl protocols
- `test_supervisord_rpc.py` - Access supervisord XML-RPC
- `test_access_binary.py` - Test internal Flask endpoints
- `test_redirect_bypass.py` - file:// redirect concept (doesn't work)

## Key Insight

The challenge name "MirrorPort" likely refers to:
- Mirroring content through SSRF (confirmed)
- Accessing services on different PORTS (partially explored)
- Some clever use of port/protocol manipulation we haven't discovered yet

With only 1.35% solve rate, the solution requires a very specific technique that's non-obvious.
