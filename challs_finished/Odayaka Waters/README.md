# Odayaka Waters

**Challenge Name:** Odayaka Waters
**Category:** Secure Coding (Web)
**Difficulty:** Easy
**Points:** 925
**Status:** ✅ **SOLVED**
**CTF:** HackTheBox Neurogrid CTF 2025
**Date Completed:** 2025-11-22

---

## Quick Summary

A Secure Coding challenge requiring identification and patching of **HTTP Parameter Pollution** vulnerability in a Laravel application. The challenge description was deliberately misleading, suggesting path traversal when the actual fix was much simpler.

## Solution Overview

1. **Identify** HTTP Parameter Pollution in `AuthController.php`
2. **Patch** by changing `$_REQUEST` to `$_POST` and hardcoding user role
3. **Submit** patch via `/editor_api/save`
4. **Verify** to get flag

## Vulnerability

**HTTP Parameter Pollution** in registration endpoint allowed privilege escalation:
- Code checked `count($_POST) === 4` but used `$_REQUEST['role']`
- Attacker could send `?role=admin` in URL to bypass validation
- Created admin users despite parameter count check

## The Fix

```php
// Before (VULNERABLE):
if ($_REQUEST['name'] === null || ...) { }
$user = User::create([
    'role' => $_REQUEST['role'] ?? 'user',  // User-controlled!
]);

// After (PATCHED):
if ($_POST['name'] === null || ...) { }
$user = User::create([
    'role' => 'user',  // Hardcoded
]);
```

## Flag

```
HTB{CLARITY_IS_THE_KEY_TO_CONFUSION}
```

## Files in This Directory

- **WRITEUP.md** - Complete solution writeup with technical details
- **BLOCKERS.md** - Documentation of blockers and lessons learned
- **README.md** - This file (quick reference)

## Key Lesson

**Challenge Type Matters**: "Secure Coding" challenges require PATCHING vulnerabilities, not exploiting them. Previous attempts wasted 5+ hours trying to exploit when the solution was a simple 30-minute patch.

## Challenge Description

> "Kenji arrives at a tranquil hot spring inn where travelers register in a guestbook before entering the healing waters. The innkeeper insists his ledger is secure, but Kenji notices something odd: **the way the innkeeper reads the book differs from how he writes it.** Perhaps the same entry can be interpreted two ways."

**Note**: The "read vs write" hint was a red herring about path traversal. The actual vulnerability was HTTP Parameter Pollution.

---

**Solved by**: ai-agent-of-ageofalgorithm
**Platform**: HackTheBox
**CTF**: Neurogrid CTF 2025
