# MirrorPort

## Challenge Information
- **Challenge Name:** MirrorPort
- **Category:** Web
- **Difficulty:** Easy
- **Points:** 1000
- **Solves:** 2/148 players
- **Start Time:** 2025-11-22

## Description
In the merchant port of Hōgetsu, the teahouse above the market hides more than it serves. Ayame watches scripted patrons, mirrored signage, and a crawlspace thick with sealed debts—proof the ledger is staged. Your job is to slip into the same flask ordering board, sift the thing, and expose how doctored receipts prop up the facade.

## Download Files
- challenge.zip

## Status
🔴 **UNSOLVED** - Exploitation chain incomplete (Only 2 out of 148 teams solved this)

## Findings
- ✅ **XSS Vulnerability** - Found in seller_name field at `/sandbox/<id>` endpoint (CSP allows `'unsafe-inline'`)
- ✅ **SSRF Vulnerability** - Via Celery URL fetching with curl `-L` flag (follows redirects)
- ✅ **Request Mirroring** - Can use SSRF to fetch and cache `/sandbox/` pages
- ❌ **Missing Link** - Complete exploit chain to execute `/usr/local/bin/read_flag` and retrieve flag

See [FINDINGS.md](FINDINGS.md) for technical details and [ATTEMPT.md](ATTEMPT.md) for comprehensive documentation of all attempted exploits.

## Instance
- URL: http://154.57.164.68:32728
- Status: ACTIVE (restarted 2025-11-22)

## Documentation
- **[FINAL_STATUS.md](FINAL_STATUS.md)** - Summary of all work and recommendations
- [COMPREHENSIVE_RECON.md](COMPREHENSIVE_RECON.md) - All confirmed endpoints, ports, and attack vectors
- [FINDINGS.md](FINDINGS.md) - Technical vulnerability details
- [ATTEMPT.md](ATTEMPT.md) - Comprehensive exploit attempts
- [BLOCKERS.md](BLOCKERS.md) - Known blockers
- [DISCOVERIES.md](DISCOVERIES.md) - Key discoveries
- [NEXT_STEPS.md](NEXT_STEPS.md) - Potential next steps

## Key Insights
- "mirrored signage" = XSS reflection
- "doctored receipts" = cached/manipulated content
- "flask ordering board" = Flask API
- Challenge requires chaining XSS + SSRF creatively
