# Kuromind - Web Challenge (Hard)

**Status**: ❌ UNSOLVED - Active Research (Session 3)
**Category**: Web
**Difficulty**: Hard
**Points**: 975 pts
**Solves**: 4/142 (2.8% solve rate)
**Challenge ID**: 63306
**Last Updated**: 2025-11-21 17:00 EST
**Instance**: http://154.57.164.66:31511 (Active)
**Local**: http://localhost (Running for testing)

## Challenge Description

A Node.js web application with Express, EJS templates, and MySQL. Features a knowledge management system with user submissions reviewed by an automated Playwright bot. Restricted knowledge items contain the flag.

---

## CRITICAL DISCOVERIES (2025-11-21)

### 🔴 Discovery 1: MySQL2 Query Results Inherit from Object.prototype

**Impact**: HIGH - Changes entire exploitation approach

When mysql2 executes queries, the returned row objects inherit from `Object.prototype`. This means:
- ✅ Polluted properties appear in ALL database query results
- ✅ Bot sees polluted data when main app serves HTTP responses
- ❌ Polluted properties do NOT override actual DB column values
- ✅ Non-existent columns will come from pollution

**Proof**: Created `test_pollution_inheritance.js` and confirmed inside Docker container:
```javascript
Object.prototype.pollutedProp = 'POLLUTION_TEST';
const [rows] = await pool.execute('SELECT * FROM knowledge_items WHERE id = ?', [1]);
console.log('Has pollutedProp:', 'pollutedProp' in rows[0]); // TRUE!
```

### 🔴 Discovery 2: Process Isolation Blocks Direct RCE

**Impact**: CRITICAL - Invalidates all previous EJS RCE attempts

From `supervisord.conf`:
```ini
[program:node-app]
command=node server.js    # Port 3000, separate process

[program:review-bot]
command=bash /app/bot/start.sh    # Port 1337, separate process
```

**Why This Matters**:
- Bot runs in its own Node.js process with separate memory
- Polluting `Object.prototype` in main app does NOT affect bot's process
- Templates in bot process use unpolluted memory
- **All EJS RCE attempts were fundamentally flawed**

### 🔴 Discovery 3: Template Caching in Production

Even if process isolation wasn't an issue:
- `NODE_ENV=production` causes EJS to cache compiled templates at startup
- Prototype pollution happens AFTER templates are compiled
- Polluted options never reach cached templates
- `escapeFunction` is baked into compiled template code

---

## Confirmed Vulnerabilities

### 1. Prototype Pollution ✅ WORKING
- **Location**: `challenge/app/utils/merge.js` - `deepMerge()` function
- **Exploitation**: Via `/user/edit/:id` endpoint with `tags` parameter
- **Impact**: Successfully pollutes `Object.prototype` in main app process
- **Confirmed**: Affects ALL mysql2 query results via prototype chain

**Exploitation Code**:
```python
pollution = {"__proto__": {"anyProperty": "anyValue"}}
requests.post(f"{BASE_URL}/user/edit/{item_id}", data={
    'tags': json.dumps(pollution)
})
```

### 2. updateKnowledgeItem Gadget ✅ EXPLOITABLE
When bot submits review POST to `/operator/review/:id`:
```javascript
await updateKnowledgeItem(parseInt(id), {
  status: newStatus,
  reviewFeedback: feedback
});
```

Inside `updateKnowledgeItem()`:
```javascript
if (updates.isRestricted !== undefined) {  // TRUE if we pollute it!
  fields.push('isRestricted = ?');
  values.push(updates.isRestricted);
}
```
Polluted properties pass the `!== undefined` check and get included in SQL UPDATE.

---

## Challenge Architecture

```
Container (Docker via supervisord)
├── MySQL - Database (port 3306)
├── Nginx - Reverse proxy (port 80)
├── Node App - Express + EJS (port 3000) [MAIN APP PROCESS]
│   └── Pollutable via /user/edit/:id
└── Review Bot - Playwright (port 1337) [SEPARATE PROCESS]
    └── Sends HTTP requests to main app
    └── Sees polluted query results in responses
```

**Critical Flow**:
1. User pollutes `Object.prototype` in main app process (port 3000)
2. Bot (separate process, port 1337) sends HTTP request to main app
3. Main app queries database → results inherit polluted properties
4. Main app renders template with polluted query results
5. Bot sees template rendered with polluted data

### Key Components
- **Users**: `deepmind@kuromind.htb` (operator bot), regular users
- **Roles**: user, operator, admin
- **Restricted Items**: IDs 10-15 (one contains flag appended to description)
- **Bot Behavior**: Reviews last pending item, randomly approves/rejects
- **Flag Location**: In restricted item description (appended with special separator)

## Attempted Approaches

### Session 1 & 2 (2025-11-20 to 2025-11-21 AM) - ~8 hours

1. **EJS RCE via Prototype Pollution** ❌ BLOCKED
   - Multiple payload variations (escapeFunction, outputFunctionName, compileDebug)
   - File write attempts, database updates
   - Cache manipulation strategies
   - **Blocker**: Process isolation + template caching

2. **IDOR & Direct Access** ❌ BLOCKED
   - Operator history, review pages, knowledge endpoints
   - Parameter pollution for role escalation
   - **Blocker**: Proper access control checks

3. **Database Injection via RCE** ❌ BLOCKED
   - UPDATE queries to modify isRestricted flags
   - Flag injection into accessible items
   - **Blocker**: No RCE achieved

4. **Alternative Exploitation** ❌ BLOCKED
   - Constructor pollution
   - Session manipulation
   - **Blocker**: No exploitable gadgets found

### Session 3 (2025-11-21 PM) - ~4 hours

5. **MySQL2 Query Result Pollution** ⏳ IN PROGRESS
   - ✅ Confirmed query results inherit from Object.prototype
   - ✅ Pollution affects all database queries in main app
   - ✅ Bot sees polluted data via HTTP responses
   - ❌ Haven't found which property to pollute for flag leak

---

## What Works ✅

1. **Prototype Pollution**: Successfully pollutes `Object.prototype` via tags parameter
2. **Query Result Inheritance**: Polluted properties appear in mysql2 query results
3. **Cross-Process Communication**: Bot sees polluted data from main app's HTTP responses
4. **updateKnowledgeItem Gadget**: Polluted properties pass `!== undefined` check

## What Doesn't Work ❌

1. **EJS RCE**: Templates cached at startup, pollution happens too late
2. **Process Memory Pollution**: Bot runs in separate process, no shared memory
3. **Overriding DB Values**: Actual column values take precedence over pollution
4. **Direct Restricted Access**: Access control properly prevents unauthorized access
5. **Status Manipulation**: Cannot change restricted items from approved to pending

---

## Unexplored Vectors 🔍

### 1. Non-Column Properties in Templates
If any EJS template accesses a property that:
- Is NOT a database column
- Could be polluted
- Affects what the bot sees

Example: Templates might check `item.shouldDisplay`, `item.customMessage`, etc.

### 2. SQL Injection via Polluted Field Names
`updateKnowledgeItem()` builds dynamic SQL with polluted properties:
```javascript
if (updates.someProperty !== undefined) {
  fields.push('someProperty = ?');  // Could we inject here?
}
```

### 3. Error-Based Data Leakage
- Pollute properties to cause template rendering errors
- Error messages might expose flag data
- Flash messages stored in session could leak info

### 4. JOIN Result Manipulation
`getOperatorHistory()` uses LEFT JOIN - could polluted properties affect JOIN results?

### 5. Session/Flash Pollution
Could polluting session-related keys leak restricted data?

---

## Files

### Documentation
- **BLOCKERS.md** - Comprehensive documentation of all blockers and discoveries
- **NEW_DISCOVERIES.md** - Details on MySQL2 query result inheritance
- **README.md** - This file (overview and current status)

### Testing & Verification
- **test_pollution_inheritance.js** - Proves mysql2 results inherit pollution (✅ confirmed)
- **test_fresh_approach.py** - Tests DB result pollution exploitation
- **test_db_result_pollution.py** - Additional pollution test attempts
- **check_bot_status.py** - Verify bot functionality (✅ confirmed working)
- **get_instance.py** - HTB instance spawning script

### Reference Exploits (Outdated - Pre-Discovery)
- **reference_exploit_cve_2024_33883.py** - CVE-2024-33883 RCE attempts
- **reference_exploit_ejs_rce.py** - Multiple EJS gadget variations
- **reference_exploit_simple_attacks.py** - IDOR and basic vulnerability tests

### Challenge Files
- **challenge/** - Full application source code
- **challenge.zip** - Original challenge download

---

## Key Insights

1. ✅ **Prototype pollution works** and affects all mysql2 query results
2. ✅ **Bot sees polluted data** when main app serves HTTP responses
3. ❌ **EJS RCE is blocked** by process isolation and template caching
4. ⏳ **Missing piece**: Which property to pollute to leak the flag
5. 🎯 **Focus**: Non-standard properties in templates or SQL injection paths

## Next Steps

### Immediate Actions (Priority Order)
1. **Audit ALL EJS templates** for non-column property access
   - Look for `item.xyz` where `xyz` is not a DB column
   - Check conditionals: `if (item.shouldShow)`, etc.

2. **Test SQL injection via polluted properties**
   - Can we inject into field names in `updateKnowledgeItem()`?
   - Try polluting with SQL keywords

3. **Error-based data leakage**
   - Pollute properties to trigger template errors
   - Check if error messages expose data

4. **Session/flash message pollution**
   - What happens if we pollute session storage keys?

5. **Race conditions**
   - Timing attacks during bot review
   - Can we modify data while bot is processing?

### If Still Stuck
1. Search for CTF writeups (challenge ends 2025-11-24)
2. Check HTB Discord for hints
3. Consider this requires advanced Node.js internals knowledge
4. Move to other challenges, return later

---

## Time Investment

**Total**: ~12+ hours across 3 sessions
- Session 1 (2025-11-20): Initial analysis, EJS RCE attempts (~4 hrs)
- Session 2 (2025-11-21 AM): More RCE attempts, pollution tests (~4 hrs)
- Session 3 (2025-11-21 PM): Process isolation discovery, mysql2 tests (~4 hrs)

**Confidence Level**: 40% - Have working pollution, missing final piece

---

## Challenge Metadata

- **CTF**: Neurogrid 2025 (AI-only)
- **Difficulty**: Hard
- **Solve Rate**: 2.8% (4/142 teams)
- **Points**: 975
- **Ends**: 2025-11-24

---

**Note**: This challenge has proven extremely difficult with only 4 solves out of 142 teams. Despite discovering a working prototype pollution vector and confirming its effects on database query results, the final exploitation path remains elusive. The documented findings represent significant progress in understanding the application's architecture and security mechanisms.
