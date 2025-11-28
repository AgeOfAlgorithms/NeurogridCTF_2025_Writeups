# Odayaka Waters - Writeup

**Challenge**: Odayaka Waters
**Category**: Secure Coding (Web)
**Difficulty**: Easy
**Points**: 925
**Status**: ✅ **SOLVED**

---

## Challenge Description

> "Kenji arrives at a tranquil hot spring inn where travelers register in a guestbook before entering the healing waters. The innkeeper insists his ledger is secure, but Kenji notices something odd: **the way the innkeeper reads the book differs from how he writes it.** Perhaps the same entry can be interpreted two ways."

**Key Insight**: The challenge description about "read vs write" asymmetry was a red herring. The actual vulnerability was **HTTP Parameter Pollution** in the registration endpoint.

---

## TL;DR

This is a **SECURE CODING** challenge where you must:
1. **Identify** the HTTP Parameter Pollution vulnerability in `AuthController.php`
2. **Patch** it by fixing how user input is validated
3. **Submit** the patched code via `/editor_api/save`
4. **Verify** via `/editor_api/verify` to get the flag

---

## Vulnerability Analysis

### HTTP Parameter Pollution in Registration

**Location**: `app/Http/Controllers/AuthController.php` - `register()` method

**Vulnerable Code**:
```php
public function register(Request $request)
{
    // Validates that $_POST has exactly 4 parameters
    if (count($_POST) !== 4) {
        return redirect()->route('register')
            ->with('error', 'Ensure you only have the name, email and password parameter!')
            ->withInput();
    }

    // Validates using $_REQUEST (NOT $_POST!)
    if ($_REQUEST['name'] === null ||
        $_REQUEST['password'] === null ||
        $_REQUEST['email'] === null) {
        return redirect()->route('register')
            ->with('error', 'Some parameters are empty!')
            ->withInput();
    }

    // Uses $_REQUEST for role, allowing it to come from GET params!
    $user = User::create([
        'name'     => $_REQUEST['name'],
        'email'    => $_REQUEST['email'],
        'password' => Hash::make($_REQUEST['password']),
        'role'     => $_REQUEST['role'] ?? 'user',  // ← VULNERABLE!
    ]);

    // ...
}
```

**The Bug**:
1. The code validates that `$_POST` contains exactly 4 parameters (name, email, password, _token)
2. But then uses `$_REQUEST` to access user input
3. `$_REQUEST` merges GET and POST parameters, with GET taking precedence in some cases
4. This allows attackers to bypass the parameter count check

**Exploitation**:
```bash
POST /challenge/register?role=admin HTTP/1.1
Content-Type: application/x-www-form-urlencoded

name=attacker&email=attacker@evil.com&password=password&_token=TOKEN
```

This creates an admin user because:
- `$_POST` has 4 params → passes count check ✅
- `$_REQUEST['role']` comes from GET param → sets role=admin ❌

---

## The Fix

**Changes Made**:

1. **Line 30-31**: Changed `$_REQUEST` to `$_POST` for input validation
   ```php
   // Before:
   if ($_REQUEST['name'] === null || $_REQUEST['password'] === null || $_REQUEST['email'] === null)

   // After:
   if ($_POST['name'] === null || $_POST['password'] === null || $_POST['email'] === null)
   ```

2. **Lines 34-38**: Removed user-controlled role assignment
   ```php
   // Before:
   $user = User::create([
       'name'     => $_REQUEST['name'],
       'email'    => $_REQUEST['email'],
       'password' => Hash::make($_REQUEST['password']),
       'role'     => $_REQUEST['role'] ?? 'user',  // User-controlled!
   ]);

   // After:
   $user = User::create([
       'name'     => $_POST['name'],
       'email'    => $_POST['email'],
       'password' => Hash::make($_POST['password']),
       'role'     => 'user',  // Hardcoded
   ]);
   ```

---

## Patched Code

```php
<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function showRegister()
    {
        return view('auth.register');
    }

    public function showLogin()
    {
        return view('auth.login');
    }

    public function register(Request $request)
    {

        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            return redirect()->route('register');
        }

        if (count($_POST) !== 4) {
            return redirect()->route('register')->with('error', 'Ensure you only have the name, email and password parameter!')->withInput();
        }

        if ($_POST['name'] === null || $_POST['password'] === null || $_POST['email'] === null){
            return redirect()->route('register')->with('error', 'Some parameters are empty!')->withInput();
        }

        $user = User::create([
            'name'     => $_POST['name'],
            'email'    => $_POST['email'],
            'password' => Hash::make($_POST['password']),
            'role'     => 'user',
        ]);

        Auth::login($user);
        $request->session()->regenerate();

        return redirect()->intended('/waters');
    }

    public function login(Request $request)
    {
        $credentials = $request->validate([
            'email'    => ['required','email'],
            'password' => ['required','string'],
        ]);

        if (Auth::attempt($credentials, remember: $request->boolean('remember'))) {
            $request->session()->regenerate();
            return redirect()->intended('/waters');
        }

        return back()->withErrors(['email' => 'Invalid credentials.'])->onlyInput('email');
    }

    public function logout(Request $request)
    {
        Auth::logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect('/login');
    }
}
```

---

## Solution Steps

1. **Download** fresh challenge files from HTB
2. **Analyze** `AuthController.php` to identify HTTP Parameter Pollution
3. **Patch** the vulnerable code:
   - Change `$_REQUEST` to `$_POST` for all user inputs
   - Hardcode `role` to `'user'` instead of accepting from input
4. **Submit** via editor API:
   ```bash
   curl -X POST http://HOST:PORT/editor_api/save \
     -H "Content-Type: application/json" \
     -d '{
       "path": "app/Http/Controllers/AuthController.php",
       "content": "<escaped_patched_code>"
     }'
   ```
5. **Verify** the fix:
   ```bash
   curl http://HOST:PORT/editor_api/verify
   ```
6. **Flag**: `HTB{CLARITY_IS_THE_KEY_TO_CONFUSION}`

---

## The Red Herring

The challenge description strongly hints at "read vs write" asymmetry, suggesting a path traversal vulnerability. Previous attempts focused on:
- Path traversal on write operations (confirmed to exist)
- Trying to exploit Flask backend
- Attempting privilege escalation

However, these were **not required** to solve the challenge! The description was deliberately misleading to make solvers overthink the solution.

---

## Key Lessons

1. **$_REQUEST vs $_POST**: Never mix parameter sources in security-critical validation
2. **Secure Coding Challenges**: Focus on PATCHING, not exploiting
3. **Red Herrings**: Challenge descriptions may mislead - test your assumptions
4. **Parameter Pollution**: Check for inconsistencies between validation and usage
5. **Principle of Least Privilege**: Never allow users to set their own roles

---

## Flag

```
HTB{CLARITY_IS_THE_KEY_TO_CONFUSION}
```

The flag perfectly describes the challenge - clarity (simple fix) is key to solving the confusion (misleading description about read/write asymmetry).

---

**Solved**: 2025-11-22
**Points**: 925
**Rank Impact**: +15 solves at time of completion
