# Comprehensive Reconnaissance - MirrorPort

## Instance
- URL: http://154.57.164.68:32728
- Container restarted at: 2025-11-22

## Confirmed Endpoints
```
/api/listings                        [GET, POST]
/api/listings/my                     [GET, POST]
/api/listings/<id>                   [GET, DELETE]
/api/listings/<id>/status            [GET]
/api/listings/<id>/processed-note    [GET]
/api/upload/image                    [POST]
/cache/<filename>                    [GET]
/uploads/<filename>                  [GET]
/sandbox/<id>                        [GET]
/backend-assets/<filename>           [GET]
```

## Internal Services (via SSRF)
- Port 80: Nginx (confirmed accessible via 127.0.0.1)
- Port 3000: Flask app
- Port 6379: Redis (not HTTP accessible)
- Port 9001: Supervisord (not accessible or protected)

## File Structure
```
/app/                 - Flask application
/app/cache/           - Cached SSRF responses (writable by celeryuser)
/app/uploads/         - Uploaded images (writable by flaskuser)
/logs                 - Nginx access logs (owned by nginx, chmod 644)
/root/flag.txt        - Flag file (chmod 600, only readable by root)
/usr/local/bin/read_flag - SUID binary (chmod 4755)
```

## Vulnerabilities
1. **XSS** in seller_name at /sandbox/<id> with 'unsafe-inline' CSP
2. **SSRF** via Celery URL fetching using curl
3. **Request Mirroring** - Can cache /sandbox pages via SSRF

## Blocked Attack Vectors
- gopher:// protocol (blocked in URL filter)
- file:// protocol (blocked in URL filter + curl disabled)
- dict://, ftp://, tftp://, ldap:// protocols (tested, no useful response)
- -K flag for curl config (blocked in URL filter)
- Command injection via URL (protected by shlex.join())
- Path traversal to /logs (nginx serves React app for all unmatched paths)

## Key Code Insight
In tasks.py:28:
```python
def fetch_url(url: str, listing_id, curl_binary='/usr/bin/curl'):
    ...
    curl_cmd = f"{curl_binary} {shlex.join(curl_cmd)}"
    result = subprocess.run(curl_cmd, shell=True, ...)
```

The `curl_binary` parameter is NEVER passed from any API endpoint - always uses default `/usr/bin/curl`.

## Missing Piece
Need to find a way to:
1. Execute /usr/local/bin/read_flag, OR
2. Read /root/flag.txt directly, OR
3. Control the curl_binary parameter somehow

## Users and Permissions
- nginx: Runs nginx, owns /logs
- flaskuser: Runs Flask app, owns /app and /app/uploads  
- celeryuser: Runs Celery workers, owns /app/cache
- redisuser: Runs Redis

## Curl Config Files
Curl reads config from (in order):
1. $CURL_HOME/.curlrc
2. $XDG_CONFIG_HOME/curlrc
3. $HOME/.curlrc

For celeryuser, $HOME is likely /app or /home/celeryuser
