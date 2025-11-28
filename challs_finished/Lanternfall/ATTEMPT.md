# Lanternfall Challenge - Attempt Summary

## Challenge Information
- **Name**: Lanternfall
- **Category**: Web
- **Difficulty**: Very Easy
- **Instance**: http://154.57.164.65:32282

## Vulnerabilities Discovered

### 1. JWT Secret Exposure (Critical)
- **Location**: `/admin-8fd9c6420ad81ca8.js` (client-side JavaScript)
- **Secret**: `ayame_moonlight_gekko_secret_key_for_jwt_signing_do_not_use_in_production_2024`
- **Impact**: Can forge JWT tokens with any role/permissions

### 2. Privilege Escalation
- Successfully created admin JWT token by modifying role claim
- Gained access to admin panel at `/admin`
- Admin token: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwidXNlcm5hbWUiOiJ0ZXN0dXNlciIsInJvbGUiOiJhZG1pbiIsImVtYWlsIjoidGVzdEB0ZXN0LmNvbSIsImlhdCI6MTc2MzY1OTE0NSwiZXhwIjoxNzYzNjYyNzQ1LCJqdGkiOiIzNDlmYmIwOS1iZTBmLTQ2YzQtOWFhMS0zMzkxZDVlYTNiMjMifQ.SPioC9Xwe0jv3DsTgFSuITwVJx9Vpubg04QlMuU-6Sw`

### 3. Command Injection via SQLite .output
- **Endpoint**: `POST /api/admin/reports`
- **Vulnerable Parameter**: `filename`
- **Exploitation**: SQLite's `.output` command accepts pipe syntax (`|command`)
- **Evidence**: Commands execute (verified by error messages and file size changes)
- **Limitation**: Cannot capture command output back into file

## Exploitation Attempts

### Command Injection Tests
1. **Basic pipe commands**:
   - `|cat`, `|sh`, `|env`, `|id`, `|whoami` - All execute successfully
   - File sizes confirm execution but no command output captured

2. **Shell command injection via user data**:
   - Registered users with commands in username/email fields containing newlines
   - Commands like `cat /flag.txt`, `base64</flag.txt`, etc.
   - When piped to `|sh` in TXT format, commands execute but output not captured

3. **File creation attempts**:
   - `echo HELLO_WORLD_TEST > /tmp/reports/test.txt`
   - `cp /flag.txt /tmp/reports/flag.txt`
   - `cat /flag.txt > /tmp/reports/output.txt`
   - All failed to create accessible files

4. **Bypass attempts for whitespace filter**:
   - Used `${IFS}` to replace spaces
   - SQLite interprets everything after as extra parameters to `.output`

### SQL Injection Attempts
- Tried `readfile('/flag.txt')` in username field
- SQL injection stored as literal string, not executed

### Other Attempts
- Checked for SSTI vulnerabilities
- Tested "script_execution" permission JWT token
- Searched for hidden endpoints (/api/flag, /api/leaks, /api/execute, etc.)
- Attempted to download database file directly

## Current Understanding

The application uses SQLite3 with command structure:
```bash
sqlite3 database.db ".output /tmp/reports/[filename]" "SELECT ..."
```

When filename is `|command`, SQLite pipes the SELECT output to the command's stdin. However, the command's stdout is not captured back into a file, making it impossible to exfiltrate data through this vector alone.

## Additional Discoveries (Session 2)

### File Download Mechanism
- Discovered `/api/admin/files?filename=X` parameter for downloading files from `/tmp/reports/`
- Successfully downloaded and analyzed all generated report files
- Only test flag `HTB{test_flag}` found in database (user ID 24)

### Tokens Endpoint
- Found `X-Lantern-Sigil` header requirement for `/api/admin/tokens` endpoint
- Successfully generated tokens with `script_execution` and `user_management` permissions
- No script execution endpoints found that utilize these permissions

### Additional Tests Performed
- Tested all valid reportTypes (user_activity, login_logs, db_stats, access_logs)
- Attempted SQL injection in reportType parameter (whitelist protected)
- Tested SQLite dot command injection in filename
- Attempted path traversal with various encoding techniques (all blocked)
- Tried URL encoding, null bytes, double encoding bypasses
- Searched for hidden endpoints and discovery files (robots.txt, etc.)
- Verified pipe commands create files but don't capture command output

### File Size Analysis
- Pipe command files show different sizes (159 bytes vs 3818 bytes)
- Size difference explained by different report formats and database growth over time
- NOT evidence of command execution capturing different outputs

## Next Steps Needed

The solution likely involves one of:
1. A vulnerability in the report generation backend that hasn't been properly exploited yet
2. An undiscovered endpoint or feature in the application
3. Some aspect of SQLite's `.output` directive behavior that allows reading /flag.txt
4. A completely different attack vector not yet considered

## Files Created
- `create_admin_token.py` - Script to forge admin JWT
- `test_filename_download.py` - Tests file download via filename parameter
- `test_tokens_with_header.py` - Tests tokens endpoint with X-Lantern-Sigil header
- Various command injection, SQL injection, and path traversal test scripts
- Downloaded report files showing only test flag, not real flag

### X-Lantern-Sigil Deep Testing (Per User Guidance)

Focused specifically on X-Lantern-Sigil header as "surely the key to the exploit":

**What X-Lantern-Sigil Enables:**
- `/api/admin/tokens` endpoint access (confirmed working)
- Generates JWTs with `script_execution` and `user_management` permissions

**Extensive Testing Performed:**
- Report generation with/without header - output identical
- File downloads with X-Lantern-Sigil - no path traversal bypass
- Custom reportTypes with header - still whitelist-protected
- Registration with header - command substitution doesn't execute
- Themed endpoints (/api/lantern, /api/sigil, etc.) - all 404
- User/flag endpoints with header - no access granted
- Script execution endpoints - none found
- Comparison of reports with/without sigil - identical output

**Only Flag Found:**
- `HTB{test_flag}` (user ID 24 in database)
- Submitted to HTB - **REJECTED** as incorrect
- Appears in 37 different report files - always the same test flag

## Session 3 Findings

**Critical Discovery: SQLite Pipes DON'T Execute Commands**

After extensive testing, confirmed that the `.output |command` syntax does NOT actually execute shell commands:
- Test with `|rev` (reverse text) returned IDENTICAL output as normal files
- All pipe commands (|tee, |cat, |rev, etc.) produce same 140-byte output
- The `|` character is treated as part of the filename, not as a pipe operator
- Previous assumptions about command execution were incorrect

**New Tests Performed:**
1. **Whitespace Bypass Attempts:**
   - `$IFS`, `${IFS}`, `${PATH:0:0}`, `$x` - Bypass whitespace filter but commands fail
   - Tab (`\t`), form feed (`\f`), vertical tab (`\v`) - Still blocked as whitespace
   - Brace expansion `|{cat,/flag.txt}` - Treated as literal filename

2. **Shell Redirect Testing:**
   - `|tee>captured.txt`, `|env>env_output.txt` - Create reports but captured files don't exist (404)
   - Redirects are part of filename, not executed by shell

3. **SQL Injection Vectors:**
   - Login/registration username fields - Stored as literals, not executed
   - Format parameter - Whitelisted to txt/json/csv only
   - ReportType parameter - Strictly whitelisted

4. **SQLite Dot Commands:**
   - Tested `.print`, `.dump`, `.schema`, `.tables`, `.databases`, `.once`
   - All return same user data - dot commands not executed, just treated as filenames

5. **Token Endpoint Testing:**
   - GET request - 405 Method not allowed
   - POST with various actions (list, dump, export) - All return 400
   - Only accepts `{username, role}` payload format

6. **Fresh Instance Analysis:**
   - Confirmed NO pre-existing data in fresh instances
   - Empty database on startup
   - No hidden admin users or flags stored by default

7. **Comprehensive Endpoint Scan:**
   - Tested 30+ potential endpoints with X-Lantern-Sigil header
   - No hidden endpoints found (/flag, /secrets, /debug, /config, etc.)
   - X-Lantern-Sigil only unlocks `/api/admin/tokens`

**Confirmed Format Support:**
- txt - Plain text columnar format
- json - JSON array format
- csv - Comma-separated values
- html/xml - NOT supported (400 error)

## Session 4 Findings (Nov 20, 2025 - New Instance)

**Instance**: http://154.57.164.74:31405 (fresh instance, 12 solves)

### Additional Testing
1. **Fresh Database Verification**: Confirmed new instances start with empty database, no pre-existing flag
2. **User ID Gap Testing**: Registered 20+ users, no gaps in IDs, no hidden users
3. **Homepage Service Analysis**: Extracted service descriptions from JavaScript, no flags in content
4. **Alternative Format Testing**: Tried special format values (sqlite, raw, readfile) - all rejected
5. **HTTP Method Testing**: POST/PUT to files endpoint - 405 Method Not Allowed
6. **Custom SQL Parameters**: Tested sql, customQuery, rawQuery with sigil - all ignored
7. **File Listing API**: Discovered `/api/admin/files` (no filename param) lists reports directory
8. **Path Traversal in Listing**: All paths normalize to reports directory

### What Session 4 Confirmed
- No flag in database (tested extensively)
- No flag in accessible filesystem
- No flag in JavaScript/HTML source
- X-Lantern-Sigil enables only `/api/admin/tokens`
- All security controls working as intended

## Status
**UNSOLVED** - After exhaustive testing across 4 sessions:
- SQLite command injection via `.output |command` does NOT work (pipes not executed)
- X-Lantern-Sigil only unlocks `/api/admin/tokens` endpoint
- No SQL injection vulnerabilities found in any parameter
- No hidden endpoints or pre-existing data in instances
- Unable to locate real flag despite comprehensive exploitation attempts
- Challenge marked "Very Easy" with 12 solves suggests missing something obvious

The fundamental exploit mechanism remains undiscovered. The challenge description mentions "craft an exploit that slips through its vigilant SQLite queries" but the actual vulnerability vector is still unknown.
