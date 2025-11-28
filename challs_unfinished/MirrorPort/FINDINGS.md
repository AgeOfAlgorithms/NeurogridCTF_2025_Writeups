# MirrorPort - CTF Challenge Findings

## Challenge Information
- **Name**: MirrorPort
- **Category**: Web (Easy)
- **Points**: 1000
- **Solves**: 2 teams
- **Instance**: http://154.57.164.72:32443

## Challenge Description
> In the merchant port of Hōgetsu, the teahouse above the market hides more than it serves. Ayame watches scripted patrons, mirrored signage, and a crawlspace thick with sealed debts—proof the ledger is staged. Your job is to slip into the same flask ordering board, sift the thing, and expose how doctored receipts prop up the facade.

**Key Phrases:**
- "mirrored signage" - reflection/duplication
- "doctored receipts" - manipulated cache files
- "flask ordering board" - Flask application
- "expose" - likely XSS or data exfiltration

## Vulnerabilities Discovered

### 1. ✅ XSS in Sandbox Endpoint
**Location**: [cache_controller.py:244](/home/sean/ctf/NeurogridCTF_2025/MirrorPort/challenge/controllers/cache_controller.py#L244)

**Vulnerable Code**:
```python
<div class="note-meta">Listing #{listing_id} • {listing.seller_name} • {listing.created_at}</div>
```

The `seller_name` field is directly interpolated into HTML without escaping.

**CSP Configuration** (Line 261-272):
```python
'Content-Security-Policy': (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "  # <-- Allows inline JS!
    "style-src 'self' 'unsafe-inline'; "
    ...
)
```

**Proof of Concept**:
```python
data = {
    "seller_name": '<script>alert("XSS")</script>',
    "scroll_name": "Test",
    "price": 1,
    "note": ""
}
# POST to /api/listings
# Visit /sandbox/<listing_id> to trigger XSS
```

**Impact**: JavaScript executes in browser with same-origin access to Flask API

### 2. ✅ SSRF via Celery URL Fetching
**Location**: [tasks.py:27-63](/home/sean/ctf/NeurogridCTF_2025/MirrorPort/challenge/tasks.py)

**How It Works**:
1. Create listing with markdown: `![](http://127.0.0.1:3000/api/listings)`
2. URL passes filter check: `url.strip(string.punctuation).startswith('http://')`
3. Celery worker fetches URL with curl
4. Response cached in `/app/cache/`
5. Accessible via `/cache/cache_{id}_{hash}{ext}`

**Limitations**:
- URLs starting with `gopher://`, `file://`, `-K`, `-k` blocked
- `shlex.join()` prevents basic command injection
- Can only fetch HTTP/HTTPS endpoints

### 3. ⚠️ Potential Nginx Alias Issue
**Location**: [nginx.conf:53-59](/home/sean/ctf/NeurogridCTF_2025/MirrorPort/challenge/nginx.conf)

```nginx
location /backend-assets/ {
    alias /app/assets/;
    try_files $uri =404;
}
```

**Status**: NOT vulnerable (both have trailing slashes)
- Classic vulnerability requires location without `/` but alias with `/`
- This configuration is safe

## Application Architecture

```
Internet → Nginx:80 → Flask:3000
                    ↓
                  Redis:6379
                    ↓
                Celery Worker (curl)
```

**Key Files**:
- `/usr/local/bin/read_flag` - SUID binary, reads `/root/flag.txt`
- `/logs` - Nginx access logs in JSON format with request body
- `/app/cache/` - Cached URL content
- `/app/uploads/` - Uploaded images

## Attack Surface Analysis

### What We Can Do:
1. ✅ Execute JavaScript via XSS in `/sandbox/<id>`
2. ✅ Make Flask fetch internal URLs via SSRF
3. ✅ Access cached responses via `/cache/`
4. ✅ Create listings with arbitrary data
5. ✅ Upload images (png, jpg, jpeg, gif, webp only)

### What We Cannot Do:
- ❌ Execute shell commands via curl injection
- ❌ Access `/root/flag.txt` directly
- ❌ Read `/logs` file via path traversal
- ❌ Use `file://`, `gopher://`, `dict://` protocols
- ❌ Access Redis directly
- ❌ Execute `/usr/local/bin/read_flag` binary

## Current Challenge

The flag is in `/root/flag.txt` which can only be read by the SUID binary `/usr/local/bin/read_flag`. We have:
1. XSS that can execute JavaScript
2. SSRF that can fetch internal HTTP endpoints

**Missing Link**: How to combine XSS + SSRF to execute `read_flag` or access its output?

## Confirmed Capabilities

### Request Mirroring (Validated)
Successfully demonstrated the "MirrorPort" concept:
1. Created listing with XSS payload in `seller_name`
2. Used SSRF to fetch that listing's `/sandbox/<id>` page
3. The XSS-containing HTML gets cached via curl
4. Cached page accessible at `/cache/cache_{id}_{hash}.html`

This confirms the "mirrored signage" and "doctored receipts" from the challenge description.

## What Was Tested (See ATTEMPT.md for details)

Extensively tested 13+ attack vectors including:
- ❌ SSTI (templates not evaluated)
- ❌ Flask debug/admin endpoints (none found)
- ❌ file:// protocol access (blocked by filter and curl)
- ❌ Path traversal to /logs (returns React app)
- ❌ Command injection (protected by shlex.join)
- ❌ Redis SSRF (no useful endpoints)
- ❌ HTTP redirect chains (file:// redirects blocked by curl CVE-2009-0037 protection)
- ❌ Environment/config file access (inaccessible)
- ❌ Comprehensive port scanning (only port 3000 accessible)

## Missing Piece

Despite finding XSS + SSRF + mirroring capability, the complete exploit chain to execute `/usr/local/bin/read_flag` and retrieve the flag remains undiscovered.

**See ATTEMPT.md for comprehensive documentation of all exploitation attempts and theories.**
