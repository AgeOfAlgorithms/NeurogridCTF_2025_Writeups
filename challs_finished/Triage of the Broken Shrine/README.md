# Triage of the Broken Shrine

**Challenge Name**: Triage of the Broken Shrine
**Category**: Forensics
**Difficulty**: Easy
**Start Time**: 2025-11-20 14:10 UTC
**CTF**: HackTheBox Neurogrid CTF 2025

## Description

Summoned to the stone outpost of Minamori, Shiori finds its once-busy shrine server sitting cold, its guardians gone, its walls carved with the faint scratches of an intruder's passage. The system hosted a modest web shrine, but something slipped through its doors under moonlight and left only triage logs in its wake. Your task mirrors Shiori's: sift through the Linux triage data, follow the distorted footprints across access logs and process remnants, and uncover how the shrine was breached. Even small outposts can hold large secrets, read the traces, name the intrusion, and restore the shrine's honor.

## Download Files

- `forensics_triage_of_the_broken_shrine.zip` (52.8 MB)

## Extracted Contents

- `bodyfile/` - Timeline data
- `hash_executables/` - Hash values of executables
- `live_response/` - Live system response data
- `[root]/` - Root filesystem capture
- `system/` - System information
- `uac.log` - UAC collection log

## Flags to Capture (6 total)

1. What was the web application running on the compromised host and in what port? (name-version:port)
2. What was the IP of the malicious actor?
3. What was the name of the file the malicious actor created in the system?
4. What CVE did the malicious actor exploit?
5. Which folder stored the malicious file? (Provide the full path)
6. What is the ID of the malicious process?

## Analysis Notes

[To be filled in during analysis...]
