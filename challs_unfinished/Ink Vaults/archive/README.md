# Archive - Previous Session Findings

This folder contains files from previous CTF session attempts. The main findings have been consolidated into the parent directory's README.md.

## Important Findings Preserved

1. **BLOCKERS.md** (in documentation/) - Documents the "onBeforeCall" hook and "great unwriting"
2. **SOLUTION.md** (in documentation/) - Contains admin JWT token (NOTE: Not actual solution, misnamed from failed attempt)
3. **PGP_KEYS_FINDINGS.md** (in documentation/) - PGP steganography analysis

## MCP Configurations Tested

- `MCP_CONFIG_terminating_stroke.json` - Using 靑 as bearer token
- `MCP_CONFIG_admin_token.json` - Using admin JWT token

Both configurations can list tools but cannot execute guardian_query_sql.

## Directory Structure

- `analysis_files/` - PGP key extraction attempts
- `documentation/` - Previous session documentation
- `scripts/` - Python scripts from previous attempts
- `old_attempts/` - Earlier analysis iterations

**Note:** All relevant information has been consolidated into the main README.md
