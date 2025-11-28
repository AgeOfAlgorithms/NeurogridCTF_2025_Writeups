# Ghidra Manual Analysis Instructions - Resurrection Challenge

## Goal
Find the 32-byte ChaCha20 encryption key used to encrypt the C2 traffic.

---

## Step 1: Load the Binary in Ghidra

1. **Open Ghidra** and create/open a project
2. **Import the binary:**
   - File → Import File
   - Select: `malware_10mb.bin` (or try `malware_proper.bin` if 10MB is too slow)
   - Format: Select "ELF" or "Raw Binary"
   - If Raw Binary:
     - Base Address: `0x00100000` (or `0x0` if unsure)
     - Language: `x86:LE:64:default`
3. **Run Auto Analysis:**
   - Analysis → Auto Analyze
   - Use default options, click "Analyze"
   - **Wait for it to complete** (this may take several minutes)

---

## Step 2: Find the ChaCha20 Constant

The ChaCha20 constant "expand 32-byte k" is at offset **0x19db60** in `malware_10mb.bin`.

### Method A: Direct Navigation
1. Press **`G`** (Go To...)
2. Enter address: `0x19db60` (or `0x0019db60`)
3. Press Enter

### Method B: String Search
1. **Search → For Strings...**
2. Check "Search All Memory Blocks"
3. Click "Search"
4. In the results, look for: `"expand 32-byte k"`
5. Double-click to navigate to it

You should see:
```
0019db60  65 78 70 61 6e 64 20 33  expand 32-byte k
0019db70  65 78 70 61 6e 64 20 33  expand 32-byte k
```

---

## Step 3: Find Cross-References (XREFs)

Once you're at the ChaCha20 constant:

1. **Right-click on the address** (or the "expand 32-byte k" text)
2. Select: **"References → Show References to Address"**
3. Or use the keyboard shortcut: **Ctrl+Shift+F** (Find References)

This shows all code locations that reference this constant.

**What to look for:**
- Function addresses that load/use this constant
- Instructions like `LEA`, `MOV`, or `LOAD` that reference `0x19db60`

**⚠️ If you see NO references:**
- The constant might be used as an immediate value
- Try searching for nearby addresses (±100 bytes)
- Or skip to Step 4 (search for crypto functions)

---

## Step 4: Find the ChaCha20 Initialization Function

Look for the function that uses the "expand 32-byte k" constant. This is where ChaCha20 cipher is initialized.

### Option A: From XREFs
- Double-click on one of the XREF entries
- This takes you to the code using the constant
- Look at the function name in the decompiler window

### Option B: Search for Crypto Functions
1. **Window → Functions** (or press F in Code Browser)
2. In the function list, search for:
   - Names containing: `chacha`, `cipher`, `crypto`, `encrypt`, `init`
   - Functions with many parameters (ChaCha20 init takes key, nonce, etc.)
3. Look for functions around **200-500 lines** of assembly

---

## Step 5: Analyze the Initialization Function

Once you find the ChaCha20 init function:

1. **Switch to Decompiler view:**
   - Window → Decompiler (or press **`Ctrl+E`**)

2. **Look for the function signature:**
   ```c
   void chacha20_init(void *cipher_state, byte *key, byte *nonce)
   ```

3. **Find where the KEY is passed:**
   - Look for a pointer/buffer being passed as the 2nd argument
   - It should be **32 bytes** (0x20)
   - Examples:
     ```c
     chacha20_init(state, &some_key_buffer, nonce);
     chacha20_init(state, local_key, local_nonce);
     ```

---

## Step 6: Trace Back to Find the Key Source

Now we need to find where `some_key_buffer` comes from:

### Method 1: Follow the Variable
1. **Right-click on the key variable** (e.g., `local_key`)
2. Select: **"References → Find References to..."**
3. Look for where it's **assigned** or **written to**

### Method 2: Look for Patterns

**Pattern A: Hardcoded Key**
```c
byte key[32] = {
    0x12, 0x34, 0x56, 0x78, ...  // 32 bytes
};
```

**Pattern B: Loaded from Data Section**
```c
key = *(undefined8 *)PTR_DAT_001234ab;
// or
memcpy(key, &DAT_00456789, 32);
```

**Pattern C: Derived with KDF**
```c
pbkdf2(password, salt, iterations, key, 32);
// or
sha256_derive(seed, key);
```

**Pattern D: XOR Obfuscated**
```c
for (i = 0; i < 32; i++) {
    key[i] = encoded_key[i] ^ mask[i];
}
```

---

## Step 7: Extract the Key

### If Key is Hardcoded:

1. **Navigate to the data address** where the key is stored
2. **Select 32 bytes** (0x20)
3. **Copy as hex:**
   - Right-click → Copy Special → Byte String (No Spaces)
   - Or use the Listing view to copy the hex bytes

### If Key is in a Global Variable:

1. **Find the variable address** (e.g., `DAT_00123456`)
2. **Navigate to that address** (press `G`, enter address)
3. **Copy 32 bytes as hex**

### If Key is XOR Encoded:

1. Find the **encoded key** bytes
2. Find the **XOR mask** bytes
3. Send me both, and I'll decode it

### If Key is Derived from Password:

1. Find the **password/seed string**
2. Find the **KDF function** (PBKDF2, HKDF, etc.)
3. Find the **parameters** (salt, iterations, hash function)
4. Send me all of these

---

## Step 8: Find the Nonce

ChaCha20 also needs a **nonce** (12 bytes for ChaCha20-IETF, or 8 bytes for original).

Look for the nonce parameter in the same init function:

```c
chacha20_init(state, key, some_nonce);
```

**Common nonce patterns:**
- **All zeros:** `00 00 00 00 00 00 00 00 00 00 00 00`
- **Counter-based:** `01 00 00 00 00 00 00 00 00 00 00 00`
- **From TCP sequence:** Derived from network packet metadata
- **From packet number:** Increments for each message

**What to send me:**
- If hardcoded: the 12 (or 8) byte hex value
- If derived: how it's calculated (e.g., "packet counter as little-endian 12 bytes")

---

## What to Send Me

Once you find the key (and nonce), reply with:

### Format:
```
KEY FOUND!

Key (32 bytes hex):
aabbccdd11223344556677889900aabbccddeeff00112233445566778899aabb

Nonce (12 bytes hex):
000000000000000000000000

OR

Nonce derivation:
"Uses packet sequence number as 12-byte little-endian value"

Location in binary:
Offset: 0x123456 (or function name: "FUN_00123456")

Notes:
[Any additional context about how the key is used]
```

### Examples:

**Example 1: Simple hardcoded key**
```
KEY FOUND!

Key: 7f65e66d7b992f00e39bd0933f6ed9732c99bf22e061c0fbf46af3aeb1c52bc0
Nonce: 000000000000000000000000
Location: Data at 0x0019dc50
```

**Example 2: XOR obfuscated**
```
KEY FOUND (XOR encoded)!

Encoded key: aabbccdd...
XOR mask: 11223344...
Nonce: all zeros
Location: Function at 0x00104abc, XOR loop at line 45
```

**Example 3: Password-derived**
```
KEY FOUND (derived)!

Password: "Resurrection"
KDF: SHA256 (single pass)
Nonce: 000000000000000000000000
Location: Function at 0x00105678
```

---

## Tips for Success

1. **Start with malware_proper.bin** if the 10MB file is too slow
2. **Be patient** - analysis may take 5-10 minutes
3. **Focus on the constant** `"expand 32-byte k"` - this is our anchor point
4. **Look for 32-byte buffers** - the key must be 32 bytes (0x20 hex)
5. **Check multiple XREFs** - if one doesn't lead to the key, try another
6. **Take screenshots** if you're unsure - I can help interpret them

---

## If You Get Stuck

Send me:

1. **Screenshot of the ChaCha20 constant location**
2. **Screenshot of any XREFs** to that constant
3. **Screenshot of the decompiled function** that uses it
4. **Any addresses or function names** you've identified

I'll guide you through the next steps!

---

## Quick Reference

| What to Find | How | Where to Look |
|--------------|-----|---------------|
| ChaCha20 constant | Search for "expand 32-byte k" | Offset 0x19db60 |
| XREFs to constant | Right-click → References | Code that uses constant |
| Init function | Follow XREFs | Function with 3+ parameters |
| Key location | Trace 2nd parameter | Data section or local buffer |
| Nonce | Trace 3rd parameter | Usually 12 or 8 bytes |

---

Good luck! Once you send me the key and nonce, I'll decrypt the C2 traffic and get the flag! 🚩
