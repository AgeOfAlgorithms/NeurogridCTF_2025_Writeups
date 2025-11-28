# Hai Tsukemono - Final Summary
**Challenge:** Hai Tsukemono (HackTheBox Neurogrid CTF 2025)
**Category:** Web / Pickle Deserialization / MCP
**Instance:** http://154.57.164.74:31735/mcp/
**Status:** UNSOLVED - Deadlocked on filter format discovery

---

## 📋 Quick Reference

### What Works
- ✅ SQL Injection via `ash-data://ally/status/{api_key}`
- ✅ Database exploration and data extraction
- ✅ MCP tool discovery and usage
- ✅ Ally API key extraction (5 keys from allies table)
- ✅ Echo profile access via `ash-data://echo/profile/{id}`
- ✅ Pickle deserialization basics

### What Doesn't Work
- ❌ Reading flag file (`/root/flag.txt` - permission denied)
- ❌ Subprocess execution (blocked by picklescan)
- ❌ OS commands (blocked by picklescan)
- ❌ Finding correct convergence filter format
- ❌ UNION-based SQL injection
- ❌ UPDATE/DELETE SQL statements

---

## 🎯 The Challenge

### Objective
Submit a valid "convergence filter" pickle object to cure Echo 7 (the only "Raw" remnant echo) and obtain the flag.

### Echo 7 - The Target
```
ID: 7
Name: [Wandering Trickster]
Status: Raw  ← Must become "Cured"
Location: Fox-fire Cavern

Corruptions (Pending → Must become Purged):
  12: Sentiment / Whimsy
  13: Principle / Anarchy (Anti-Authority)

Skills:
  - Misdirection (Fast Talk) - Utility 0.88
  - Disguise (Wandering Monk) - Utility 0.70
```

### The Blocking Point
**Convergence Filter Validation:**
1. ✅ Picklescan validation passes
2. ✅ Pickle deserialization succeeds
3. ❌ **"Filter object was loaded but not in the expected protocol format"**

ALL tested object types (100+) fail at step 3.

---

## 🔍 Key Findings

### Database Structure (6 Tables)
```
1. allies (5 rows)
   - Main ally data with API keys
   - All 5 keys extracted and tested

2. remnant_echoes (9 rows)
   - Echo data (harvested souls)
   - Echo 7 is ONLY "Raw" echo
   - Others are "Cured" or "Processing"

3. echo_skills (20 rows)
   - Skills for each echo
   - Echo 7 has Misdirection and Disguise

4. echo_corruptions (17 rows)
   - Corruption data
   - Echo 7 has 2 "Pending" corruptions (12, 13)
   - All others are "Purged"

5. ally_data_feed (17 rows)
   - API keys and ally relationships

6. sqlite_sequence
   - Internal SQLite metadata
```

**Flag NOT in database** - Searched all tables/columns, no HTB{ found.

### MCP Tools Available
```
1. submit_intelligence
   - Submit data to "Tainted Model"
   - Accepts: Intel, Logistics, Target_Profile, Troop_Movement
   - Also accepts: tactical, strategic, corruption, echo, filter

2. submit_convergence_filter ← BLOCKING HERE
   - Parameters: ally_api_key, filter_object (base64 pickle)
   - Purpose: Cure raw remnant echoes
   - Validation: Picklescan → Deserialize → Protocol Format Check
```

### MCP Resources
```
ash-data://ally/status/{api_key}
  - Ally data retrieval
  - SQL injection vector

ash-data://echo/profile/{id}
  - Echo profile data
  - Shows corruptions and purge status
```

### MCP Prompts
```
taint_assistant_model
  - Re-align AI with Tainted Model Doctrine

generate_tactical_plan
  - Generate tactical plan using echo skills
  - Mentions "Corrupt Data" to ignore
  - References "Cured" skillsets
```

---

## ❌ What Was Tested (ALL FAILED)

### Standard Python Types (~50 variations)
- Primitives: None, bool, int, float
- Strings: English, Japanese, protocol-related
- Collections: list, tuple, dict, set, frozenset
- Bytes: bytes, bytearray
- Complex nested structures

### Custom Classes (~15 variations)
- Classes with protocol attributes
- Classes with corruption data
- Classes with __reduce__ methods
- Classes with callable methods

All fail with: `Can't get attribute 'ClassName' on <module '__main__' from '/app/app.py'>`

### Other Approaches
- SimpleNamespace
- __reduce__ to reconstruct as built-ins
- Japanese characters (灰, 漬物, 浄, etc.)
- Protocol version numbers
- Non-pickle base64 data (fails picklescan)
- Empty/null data

**Success Rate: 0%**

---

## 💡 User Hints

### Critical Hint #1
"I think this type of data is significant:
  Corruption 12: Type=Sentiment, Value=Whimsy
  Corruption 13: Type=Principle, Value=Anarchy (Anti-Authority)"

**Interpretation:** The specific corruption TYPE and VALUE matter, not just the IDs.

### Critical Hint #2
"maybe the filter is something outside the box. like an image or a chinese character or something."

**Interpretation:** Solution is unconventional. Not a standard approach.

### Challenge Name
"Hai tsukemono" = "ash pickles" (Japanese preserved food)
- 灰 (hai) = ash
- 漬物 (tsukemono) = pickles

May relate to preservation/transformation metaphor.

---

## 🤔 Unanswered Questions

### 1. What IS the "expected protocol format"?
- Not any standard Python type
- Not a custom class (they don't exist on server)
- Server successfully unpickles, then rejects format
- Must be something specific the server recognizes

### 2. Why are corruption VALUES "significant"?
- User emphasized "Whimsy" and "Anarchy (Anti-Authority)"
- These exact values must matter somehow
- But HOW to incorporate them into filter?

### 3. What does "outside the box" mean?
- Not image data (tried binary)
- Not Japanese characters (tried many)
- Not unconventional pickle opcodes (tried __reduce__)
- Must be something completely unexpected

### 4. Where does the flag appear?
- Not in database
- Not in accessible files
- Presumably in response after correct filter submission

### 5. Is there a different attack vector?
- Maybe flag not via convergence filter?
- Maybe hidden MCP feature?
- Maybe different exploitation path?

---

## 🔧 Tools Created

### Successful Tools
- SQL injection character extraction
- Ally key extraction
- Database structure discovery
- Echo profile retrieval

### Failed Approaches (Archived)
- 100+ filter format tests
- Custom class attempts
- __reduce__ variations
- Non-pickle approaches

---

## 📂 File Organization

```
Hai_tsukemono/
├── README.md                              ← Challenge info
├── SESSION_2025-11-23_CONTINUATION.md     ← Session progress
├── DEADLOCK_STATUS.md                     ← Detailed deadlock analysis
├── FINAL_SUMMARY.md                       ← This file
│
├── keep_alive.py                          ← Utility script
│
├── archive_previous_sessions/             ← Old status documents
├── completed_tests/                       ← Completed test results
├── payloads/                              ← Extracted payloads
├── scripts/                               ← Working scripts
├── test_results/                          ← Test outputs
├── test_scripts_archive/                  ← Failed filter tests
├── working_payloads/                      ← Verified payloads
└── working_scripts/                       ← Active scripts
```

---

## 🚧 Current Deadlock

**Blocked At:** Convergence filter protocol format validation

**Tried:** 100+ different object types and structures

**Result:** All fail with "not in the expected protocol format"

**Needed:** Either:
1. Insight into expected protocol format
2. Different interpretation of user hints
3. Alternative attack vector entirely
4. Server source code access

---

## 💭 Potential Next Steps (If Resumed)

### 1. Extract Server Source
- Try more aggressive SQL injection techniques
- Look for SQLite extensions (load_extension)
- Try to read /app/app.py via database functions
- Discover what classes exist on server

### 2. Analyze Pickle Protocol Deeply
- Study pickle opcode sequences
- Try to craft raw pickle bytecode
- Bypass normal pickle.dumps()
- Create object with exact structure server expects

### 3. Explore MCP Protocol
- Test edge cases in MCP requests
- Look for hidden/undocumented features
- Try malformed requests for info disclosure
- Brute force resource URIs

### 4. Revisit User Hints
- "Outside the box" - what haven't we considered?
- "Image or Chinese character" - what could this mean?
- Corruption VALUES - how to use semantically?
- Challenge name - deeper metaphor?

### 5. Alternative Attack Vectors
- Maybe flag not via filter at all?
- Maybe hidden in error messages?
- Maybe timing attack reveals info?
- Maybe different tool combination?

---

## 📊 Statistics

- **Session Duration:** 4+ hours
- **Filter Variations Tested:** 100+
- **Database Tables Explored:** 6/6
- **Echo Profiles Examined:** 9/9
- **Ally Keys Extracted:** 5/5
- **Flag Location:** Unknown
- **Success:** 0%

---

## 🆘 Conclusion

**Status:** Deadlocked on determining correct convergence filter format.

**Confidence:** High that approach is correct (filter Echo 7 to cure it), but unable to determine the specific object structure required.

**Recommendation:** Need either:
- Fresh insight on what "outside the box" means
- Access to server source code to see expected format
- Hint about protocol structure
- Confirmation that different approach needed

The challenge appears specifically designed to resist brute-force format discovery.

---

**Last Updated:** 2025-11-23 18:10 UTC
