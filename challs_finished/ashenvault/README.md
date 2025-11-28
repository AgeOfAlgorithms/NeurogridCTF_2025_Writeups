# ashenvault

**Challenge Name:** ashenvault
**Category:** Web
**Difficulty:** Medium
**Status:** ✅ Solved

## Description
The Whisper Network carries messages across Kurozan's empire, recording every movement and decree in silence. It has no voice of its own, yet it remembers everything spoken through it.

## Challenge Information
- **Challenge ID:** 63309
- **CTF:** Neurogrid CTF 2025 (HackTheBox)
- **Vulnerability:** CVE-2025-24813 (Tomcat Session Deserialization) + Groovy @ASTTest RCE
- **Flag:** HTB{CVE-2025-24813_plus_gr0vy_met4_pr0gramming_is_the_best_021966025225902b828cb944cf914859}
- **Points:** 1000

## Solution Summary
This challenge exploits CVE-2025-24813 in Apache Tomcat 9.0.98, which allows uploading arbitrary files via partial PUT requests when `readonly=false`. Combined with Tomcat's FileStore session persistence and a vulnerable Groovy deserialization sink, we achieve RCE using the `@groovy.transform.ASTTest` annotation that executes code during compile-time AST transformation.

## Files
- **web_ashenvault.zip** - Original challenge download
- **exploit/** - Exploit tools
  - `GeneratePayload.java` - Generates malicious serialized payload
  - `exploit.py` - Uploads payload and triggers deserialization
  - `demo-1.0-SNAPSHOT.jar` - Required dependency for compilation
- **WRITEUP.md** - Detailed writeup with exploitation steps

## Usage

```bash
# Navigate to exploit directory
cd exploit/

# Compile payload generator
javac -cp "demo-1.0-SNAPSHOT.jar:." GeneratePayload.java

# Generate malicious payload
java -cp "demo-1.0-SNAPSHOT.jar:." GeneratePayload

# Run exploit against target
python3 exploit.py http://target:port
```

See [WRITEUP.md](WRITEUP.md) for detailed analysis and exploitation steps.
