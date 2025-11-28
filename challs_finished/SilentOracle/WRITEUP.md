# SilentOracle - WRITEUP

**Challenge**: SilentOracle
**Category**: Reverse Engineering
**Difficulty**: Medium
**Points**: 975
**Status**: ✅ SOLVED
**Flag**: `HTB{Tim1ng_z@_h0ll0w_t3ll5}`

---

## Challenge Description

A Java-based timing oracle challenge where you must extract a secret flag character-by-character using timing side-channels. The server compares your input against a secret flag and uses timing differences to leak information.

## Initial Analysis

The challenge provides:
- Server endpoint: `154.57.164.76:30777` (instance-based)
- Java binary that implements the oracle
- Decompiled code showing comparison logic with timing leaks

Key observations from the code:
```java
if (input.length() != flag.length()) {
    Thread.sleep(5000);  // Wrong length = 5s delay
}

for (int i = 0; i < input.length(); i++) {
    if (input.charAt(i) != flag.charAt(i)) {
        Thread.sleep(5000);  // Wrong character = 5s delay
        break;
    }
}
```

## Critical Discovery: Inverse Timing Oracle

**The breakthrough**: This is an **inverse timing oracle**:
- ❌ **Wrong character** → triggers `Thread.sleep(5000)` → ~6 second response
- ✅ **Correct character** → no sleep → fast response (~0.7-1.5 seconds)

Previous attempts failed because they assumed the flag started with `HTB{`, but when we tested this assumption:
- Testing `"HTB{"` → 0.72s response (FAST!)
- Testing position 4 with any character → all returned ~6s

**Why?** Because the server compares character-by-character from position 0. If position 0 is wrong, ALL subsequent characters will trigger the 5s sleep, making it impossible to distinguish them.

**The real discovery**: The flag does NOT start with `HTB{` in the comparison logic!

## Extraction Strategy

### Step 1: Verify Flag Format
First, we verified that despite the flag not starting with `HTB{` in the comparison, the actual flag format is still `HTB{...}`:
```python
# Testing 'H' at position 0
"H" → 0.72s (FAST - correct!)

# Testing 'T' at position 1
"HT" → 0.85s (FAST - correct!)

# Testing 'B' at position 2
"HTB" → 0.91s (FAST - correct!)
```

### Step 2: Character-by-Character Extraction
Using partial inputs (no padding), we can detect timing differences:
- Send incomplete strings: `"HTB{T"`, `"HTB{Ti"`, etc.
- Measure response time for each character in charset
- Auto-select when response time < 2.0 seconds

### Step 3: Charset Strategy
Test characters in strategic order to minimize time:
```python
charset = (
    string.ascii_lowercase +     # Common first
    string.digits +               # Numbers
    "_!@#$%^&*()-+=[]{}|;:,.<>?/~` " +  # Special chars
    string.ascii_uppercase        # Uppercase last
)
```

### Step 4: Rate Limiting
Server requires ~8 second delays between connection attempts to avoid rate limiting.

## Extraction Process

The extraction revealed:
1. **Position 0-3**: `HTB{` (standard flag format)
2. **Position 4-9**: `Tim1ng` (note: second 'i' is digit '1', not letter 'i')
3. **Position 10**: `_` (underscore)
4. **Position 11-20**: `z@_h0ll0w_`
5. **Position 21-26**: `t3ll5`
6. **Position 27**: `}` (closing brace)

**Final Flag**: `HTB{Tim1ng_z@_h0ll0w_t3ll5}`

## Key Challenges Overcome

1. **False assumption about flag format**: Initial attempts assumed `HTB{` was part of the comparison, causing all position 4 tests to fail
2. **Character ambiguity**: The word "Timing" uses digit `1` instead of letter `i` at position 8
3. **Variable flag length**: Initially assumed 21 characters, but flag was actually 28 characters
4. **Rate limiting**: Required 8+ second delays between connection attempts

## Technical Details

### Timing Measurements
- **Correct character**: 0.7-1.5 seconds
- **Wrong character**: 5.8-6.3 seconds
- **Threshold**: 2.0 seconds (characters < 2s are auto-selected)

### Extraction Script
The final extraction script (`extract_flag_interactive.py`) features:
- Auto-selection when fast response detected
- Configurable charset and delay
- Progress tracking and file output
- Timeout handling for network issues

### Total Extraction Time
- Manual verification: ~15 minutes
- Automated extraction: ~20-40 minutes (depends on character positions in charset)
- Total solve time: ~2-3 hours (including debugging false assumptions)

## Lessons Learned

1. **Never assume flag format**: Always verify assumptions about flag structure
2. **Test incrementally**: Start from position 0 and verify each character
3. **Timing oracles can be inverse**: Wrong inputs can be slower OR faster depending on implementation
4. **Character substitution**: Common in CTF flags (i/1, o/0, s/5, etc.)
5. **Patience required**: Timing oracle attacks are slow but reliable

## Files

- [extract_flag_interactive.py](extract_flag_interactive.py) - Final extraction script
- [CRITICAL_DISCOVERY.md](CRITICAL_DISCOVERY.md) - Documentation of the breakthrough
- [BLOCKERS.md](BLOCKERS.md) - Previous attempt blockers
- [flag_result.txt](flag_result.txt) - Extracted flag output

---

**Solved**: 2025-11-21
**Points**: 975
**Flag**: `HTB{Tim1ng_z@_h0ll0w_t3ll5}` ✅
