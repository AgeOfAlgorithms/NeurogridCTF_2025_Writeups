# Manual - CTF Writeup

**Challenge:** Manual
**Category:** Forensics/Malware Analysis
**Difficulty:** Very Easy
**Points:** 975
**Status:** ✅ SOLVED

---

## Challenge Description

When a courier is found ash-faced on the cedar road, Shiori discovers a "tradesman's manual" folded in his sleeve, plain instructions on the outside, but inside a strange script of symbols and percent signs meant for a machine. The scroll is an obfuscated BAT attachment in disguise, a batch charm that only reveals its purpose once its knots are untied. Follow Shiori's lead: de-tangle the lines, read what the script truly does, and trace where its "manual" tries to send the unwary. In the shadows of Kageno, even a simple instruction sheet can open a door.

**Files:** `forensics_manual.zip` → `tradesman_manual.bat`

---

## Solution Summary

The challenge involved deobfuscating a heavily obfuscated Windows batch file that contained a PowerShell payload. The flag was embedded within the decoded PowerShell script as part of a malicious C2 URL.

**Flag:** `HTB{34dsy_d30bfusc4t10n_34sy_d3t3ct10n}`
**Meaning:** "easy deobfuscation easy detection" (leet speak)

---

## Analysis

### 1. Initial Examination

The batch file `tradesman_manual.bat` (128 lines) uses multiple layers of obfuscation:

- **Variable naming obfuscation:** Variables are constructed using a pattern like `%BASE%letter1%BASE%letter2%BASE%letter3%BASE%`
- **Base64 encoding:** PowerShell payload is base64-encoded
- **Separator injection:** The string `djlrttmeqqkr` (12 characters) is inserted throughout the base64 to break pattern matching
- **Delayed expansion:** Uses `!qoz!` which expands to `set` command
- **Split payload:** The base64 is split across 104 different variables (lines 15-118)

### 2. Obfuscation Technique Details

#### Variable Naming Scheme

```batch
!qoz! %FTW%b%FTW%y%FTW%o%FTW%=<content>
```

This creates a variable named `byo` (formed by concatenating the letters between `%` signs).

#### Separator Pattern

The obfuscation uses several variants of the separator:
- `djlrttmeqqkr` (full, 12 chars)
- `vjlrttmeqqkr` (with 'v' prefix)
- `jlrttmeqqkr` (partial)
- Split variants: `djlrttme` + `eqqkr`

#### Execution Flow

Line 125 concatenates 110 variables in a specific order:
```batch
%qdu%%ssf%%gfw%%yrh%%dnx%%mqn%%vpr%%ahy%%fmy%...
```

This builds the complete PowerShell execution command.

### 3. Deobfuscation Process

#### Step 1: Extract Variable Assignments

Used regex to extract all variable assignments:
```python
match = re.search(r'!qoz!\s+%([^%]+)%([^%])%\1%([^%])%\1%([^%])%\1%=(.+)', line)
var_name = match.group(2) + match.group(3) + match.group(4)
```

This correctly identifies 104 variables from lines 15-118.

#### Step 2: Concatenate in Correct Order

Extract the variable order from line 125:
```python
var_order = re.findall(r'%([^%]+)%', line125)
```

Concatenate all variable contents in this order.

#### Step 3: Remove Separators

Remove all separator patterns from the concatenated string:
```python
cleaned = full_content.replace('djlrttmeqqkr', '')
```

Result: A PowerShell command starting with:
```
-NoProfile -WindowStyle Hidden -NonInteractive -ExecutionPolicy Bypass -Command "$s='...'
```

#### Step 4: Extract Base64 Payload

The concatenated result is a PowerShell command, not raw base64. Extract the `$s` variable:
```python
pattern = r'\$s=\'([^\']+)\''
match = re.search(pattern, full_clean)
base64_payload = match.group(1)
```

#### Step 5: Decode Base64

Decode the extracted base64 as UTF-16 LE (PowerShell default):
```python
decoded_bytes = base64.b64decode(base64_payload)
decoded_text = decoded_bytes.decode('utf-16-le')
```

### 4. Flag Location

The flag appears in the decoded PowerShell script as part of a C2 URL:

```powershell
$anaba = Join-Path $env:USERPROFILE 'aoc.bat'
$uri    = 'http://malhq.htb/HTB{34dsy_d30bfusc4t10n_34sy_d3t3ct10n}'
```

---

## Key Breakthrough

The critical insight was understanding that **the concatenated variables form a complete PowerShell command**, not raw base64 data. Previous attempts failed because they tried to decode the entire concatenated string directly as base64, instead of first extracting the base64 payload from within the PowerShell command structure.

The deobfuscation hierarchy:
```
Batch variables → PowerShell command → Base64 string → UTF-16 LE → Decoded script → Flag
```

---

## Malware Behavior Analysis

The decoded PowerShell script reveals the malware's intended behavior:

1. **Persistence:** Creates `aoc.bat` in user profile directory
2. **C2 Communication:** Connects to `malhq.htb` (malicious HQ domain)
3. **Data Exfiltration:** Downloads additional payload from C2 server
4. **Execution:** Uses `Invoke-WebRequest` with basic parsing to fetch content
5. **Obfuscation:** Multiple layers to evade static analysis

**IOCs (Indicators of Compromise):**
- C2 Domain: `malhq.htb`
- Persistence file: `aoc.bat`
- Separator signature: `djlrttmeqqkr`

---

## Solution Script

The final working deobfuscation script: [`analyze_command.py`](analyze_command.py)

Key functions:
- Extract all 104 variables using correct regex
- Concatenate in line 125 order
- Remove separator patterns
- Extract `$s` variable from PowerShell command
- Decode base64 as UTF-16 LE
- Search for flag pattern

---

## Lessons Learned

1. **Don't assume data structure:** The concatenated result wasn't raw base64 - it was a complete PowerShell command containing base64
2. **Follow execution order:** Line 125 defines the exact concatenation order
3. **Understand variable naming:** The pattern `%BASE%x%BASE%y%BASE%z%BASE%` was key to extraction
4. **Multiple separator variants:** Had to remove several variations of the separator pattern
5. **Proper encoding:** PowerShell defaults to UTF-16 LE for base64 decoding

---

## Timeline

- **Initial attempts:** Tried to decode concatenated string as raw base64 → UTF-16 errors
- **Breakthrough:** Realized the result is a PowerShell command, not base64
- **Solution:** Extracted `$s` variable, decoded separately
- **Flag found:** Embedded in C2 URL within decoded PowerShell script

---

## Tools Used

- Python 3 with `base64` and `re` modules
- Manual batch file analysis
- Regex pattern matching for variable extraction

---

## Flag Submission

```
HTB{34dsy_d30bfusc4t10n_34sy_d3t3ct10n}
```

**Points awarded:** 975
**Status:** ✅ Successfully submitted
