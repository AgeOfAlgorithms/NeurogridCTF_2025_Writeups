# Odayaka Waters - Solution Summary

## Challenge Information
- **Name**: Odayaka Waters
- **Category**: Secure Coding (Web)
- **Difficulty**: Easy
- **Points**: 925
- **Flag**: `HTB{CLARITY_IS_THE_KEY_TO_CONFUSION}`

## The Vulnerability

**HTTP Parameter Pollution** in `app/Http/Controllers/AuthController.php`

The code mixes `$_POST` and `$_REQUEST`, allowing attackers to bypass parameter validation by sending data through different sources (GET vs POST).

## Vulnerable Code (Lines 27-40)

```php
// Checks only $_POST count
if (count($_POST) !== 4) {
    return redirect()->route('register')->with('error', 'Ensure you only have the name, email and password parameter!')->withInput();
}

// Validates using $_REQUEST (merges GET + POST!)
if ($_REQUEST['name'] === null || $_REQUEST['password'] === null || $_REQUEST['email'] === null){
    return redirect()->route('register')->with('error', 'Some parameters are empty!')->withInput();
}

// Uses $_REQUEST for role - VULNERABLE!
$user = User::create([
    'name'     => $_REQUEST['name'],
    'email'    => $_REQUEST['email'],
    'password' => Hash::make($_REQUEST['password']),
    'role'     => $_REQUEST['role'] ?? 'user',  // ← Can be controlled via GET param
]);
```

## Exploitation

```bash
POST /challenge/register?role=admin HTTP/1.1
Content-Type: application/x-www-form-urlencoded

name=attacker&email=attacker@evil.com&password=pass123&_token=TOKEN
```

Result: Admin user created despite 4-parameter validation

## The Fix

**Two changes required:**

### Change 1: Use $_POST consistently (Line 30-31)
```php
// Before:
if ($_REQUEST['name'] === null || $_REQUEST['password'] === null || $_REQUEST['email'] === null)

// After:
if ($_POST['name'] === null || $_POST['password'] === null || $_POST['email'] === null)
```

### Change 2: Hardcode role assignment (Line 34-38)
```php
// Before:
$user = User::create([
    'name'     => $_REQUEST['name'],
    'email'    => $_REQUEST['email'],
    'password' => Hash::make($_REQUEST['password']),
    'role'     => $_REQUEST['role'] ?? 'user',  // User-controlled
]);

// After:
$user = User::create([
    'name'     => $_POST['name'],
    'email'    => $_POST['email'],
    'password' => Hash::make($_POST['password']),
    'role'     => 'user',  // Hardcoded
]);
```

## Deployment Steps

1. **Create patched file** with fixes applied
2. **Submit via API**:
   ```bash
   curl -X POST http://HOST:PORT/editor_api/save \
     -H "Content-Type: application/json" \
     -d '{
       "path": "app/Http/Controllers/AuthController.php",
       "content": "<escaped_patched_code>"
     }'
   ```
3. **Verify**:
   ```bash
   curl http://HOST:PORT/editor_api/verify
   # Returns: {"flag": "HTB{CLARITY_IS_THE_KEY_TO_CONFUSION}"}
   ```

## Common Mistakes to Avoid

1. ❌ **Trying to exploit instead of patch** - This is Secure Coding, not Web exploitation
2. ❌ **Focusing on path traversal** - The description was a red herring
3. ❌ **Looking for Flask backend source** - Not needed for this challenge
4. ❌ **Only partial fix** - Must fix BOTH $_REQUEST usages

## Why It Works

- **Parameter Pollution Fixed**: Using only `$_POST` prevents GET parameter injection
- **Role Hardcoded**: Removes user control over privilege level
- **Validation Consistent**: Same source (`$_POST`) used for validation and data access

## Security Best Practices Demonstrated

1. **Never mix parameter sources** (`$_REQUEST` vs `$_POST`) in security contexts
2. **Validate and use from same source** to prevent pollution attacks
3. **Never trust user input** for security-critical fields like roles
4. **Principle of least privilege**: Hardcode safe defaults, don't allow escalation

## References

- Patched code: `AuthController_PATCHED.php`
- Full writeup: `WRITEUP.md`
- Blockers document: `BLOCKERS.md`
- Challenge files: `odayaka_waters/`
