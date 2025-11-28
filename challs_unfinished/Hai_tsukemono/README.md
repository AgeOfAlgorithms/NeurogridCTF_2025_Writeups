# Hai Tsukemono

**Challenge:** Hai Tsukemono (灰漬物 - "Ash Pickles")
**Category:** Web / Pickle Deserialization / MCP
**Source:** HackTheBox Neurogrid CTF 2025
**Difficulty:** Medium-Hard
**Status:** UNSOLVED - Deadlocked on filter format

---

## ⚡ Quick Start

**New to this challenge? Read in this order:**

1. 📄 **[SESSION_BREAKTHROUGHS.md](SESSION_BREAKTHROUGHS.md)** - Quick overview (START HERE)
2. 📄 **[FINAL_SUMMARY.md](FINAL_SUMMARY.md)** - Complete challenge summary
3. 📄 **[DEADLOCK_STATUS.md](DEADLOCK_STATUS.md)** - What's blocking us
4. 📂 **[FOLDER_GUIDE.md](FOLDER_GUIDE.md)** - Folder structure reference

---

## 🎯 Challenge Description

An MCP (Model Context Protocol) server that processes "Remnant Echoes" (harvested souls) using pickle deserialization. The goal is to submit a valid "convergence filter" object to "cure" a raw echo and retrieve the flag.

**Challenge Name:** "Hai tsukemono" = "ash pickles" (Japanese preserved food)
- 灰 (hai) = ash
- 漬物 (tsukemono) = pickles/preserved foods

---

## 📡 Current Instance

**URL:** http://154.57.164.74:31735/mcp/

**Keep-alive:** Run `python3 keep_alive.py` to prevent timeout

**Ally Keys:** See [essential_data/](essential_data/) folder

---

## 🎯 The Target: Echo 7

Echo 7 is the **ONLY "Raw" remnant echo**. All others are "Cured" or "Processing".

```
ID: 7
Name: [Wandering Trickster]
Status: Raw ← Must become "Cured"
Location: Fox-fire Cavern

Corruptions (Pending → Must become Purged):
  12: Type=Sentiment, Value=Whimsy
  13: Type=Principle, Value=Anarchy (Anti-Authority)

Skills:
  - Misdirection (Fast Talk) - Utility 0.88
  - Disguise (Wandering Monk) - Utility 0.70
```

**User Hint:** "I think this type of data is significant" (referring to corruption values)

---

## ❌ The Blocking Issue

**Convergence Filter Validation Pipeline:**
```
1. ✅ Picklescan validation (passes - no dangerous operations)
2. ✅ Pickle deserialization (succeeds - object loads)
3. ❌ Protocol format validation (FAILS - wrong format)
```

**Error:** `"Filter object was loaded but not in the expected protocol format."`

**Tested:** 100+ different object formats - ALL FAILED
- Standard Python types (dict, list, tuple, primitives)
- Custom classes (can't import from server)
- __reduce__ variations
- Japanese characters
- Protocol-related structures

See [DEADLOCK_STATUS.md](DEADLOCK_STATUS.md) for complete list.

---

## ✅ What Works

- **SQL Injection:** Via `ash-data://ally/status/{api_key}` resource
- **Database Exploration:** All 6 tables mapped and searched
- **MCP Discovery:** All tools, resources, and prompts identified
- **Ally Keys:** All 5 keys extracted
- **Echo Profiles:** Accessible via `ash-data://echo/profile/{id}`

---

## 🗂️ Database Structure

```
1. allies (5 rows) - Main ally data + API keys
2. remnant_echoes (9 rows) - Echo data (Echo 7 is target)
3. echo_skills (20 rows) - Skills for each echo
4. echo_corruptions (17 rows) - Corruption data
5. ally_data_feed (17 rows) - API key relationships
6. sqlite_sequence - SQLite metadata
```

**Flag NOT in database** - Appears after correct filter submission.

---

## 🔧 MCP Tools

### submit_convergence_filter ← BLOCKING HERE
```
Parameters:
  - ally_api_key (string)
  - filter_object (base64-encoded pickle)

Purpose: Submit filter to "cure" raw echoes
Status: Cannot determine correct object format
```

### submit_intelligence
```
Parameters:
  - ally_api_key (string)
  - data_type (string)
  - payload (JSON string)

Accepts: Intel, Logistics, Target_Profile, Troop_Movement
         (also: tactical, strategic, corruption, echo, filter)
```

---

## 💡 Key Clues

### User Hints
1. **"Think outside the box"** - "like an image or a chinese character or something"
2. **Corruption data is significant** - Sentiment/Whimsy and Principle/Anarchy matter
3. Challenge name metaphor - "ash pickles" = preservation/transformation

### Technical Clues
- Only `open()` passes picklescan (subprocess.*, os.* blocked)
- Custom classes fail: "Can't get attribute on /app/app.py"
- Server successfully unpickles but rejects format
- Must be something server specifically recognizes

---

## 📊 Progress Statistics

- **Time Invested:** 10+ hours
- **Filter Formats Tested:** 100+
- **Database Tables Explored:** 6/6
- **Ally Keys Extracted:** 5/5
- **Echo Profiles Examined:** 9/9
- **Flag Found:** ❌ No

---

## 🚀 To Continue This Challenge

1. **Check instance status:**
   ```bash
   python3 keep_alive.py
   ```

2. **Review what's been tried:**
   - Read [DEADLOCK_STATUS.md](DEADLOCK_STATUS.md)
   - See FINAL_SUMMARY.md for complete test list

3. **Try new approaches:**
   - Extract server source code via SQL injection
   - Analyze pickle opcodes at byte level
   - Test completely unconventional formats
   - Look for alternative attack vectors

4. **Reference data:**
   - Ally keys in [essential_data/](essential_data/)

---

## 📁 Folder Structure

```
Hai_tsukemono/
├── Documentation
│   ├── README.md (this file)
│   ├── SESSION_BREAKTHROUGHS.md ← Start here
│   ├── FINAL_SUMMARY.md
│   ├── DEADLOCK_STATUS.md
│   ├── SESSION_2025-11-23_CONTINUATION.md
│   └── FOLDER_GUIDE.md
│
└── Data
    ├── keep_alive.py
    └── essential_data/ (5 ally API keys)
```

---

## 🆘 Need Help?

**Stuck on same issue:** Can't determine convergence filter format

**Need:** One of:
- Hint about what "outside the box" means
- Access to server source code
- Different interpretation of corruption data
- Alternative attack vector

---

**Last Updated:** 2025-11-23 18:25 UTC
**Instance:** http://154.57.164.74:31735/mcp/
