# Secret Meeting - File Inventory

## Challenge Files
- `README.md` - Challenge description and flag questions
- `memory.raw` (5GB) - Windows memory dump
- `image.001` (2.1GB) - NTFS disk image with VSS snapshot

## Documentation
- `INVESTIGATION_SUMMARY.md` - Comprehensive investigation findings and status
- `WRITEUP.md` - Detailed writeup of solved flags (Flags 1-3)
- `FILE_INVENTORY.md` - This file

## Evidence Files (Extracted from VSS)
- `Zoom.us.ini` - Contains DPAPI-encrypted database key (ZWOSKEY)
- `zoomus.enc.db` (112KB) - SQLCipher encrypted database (LOCKED)
- `zoom_memlog_3376_20250306-172649.log.zenc` (110KB) - Encrypted log file
- `viper.ini` - VMware network adapter configuration
- `client.config` - Zoom client settings
- `NTUSER.DAT` - User registry hive
- `hash.txt` - NT hashes for all user accounts

## Decryption Results
- `zoom_key_DECRYPTED.bin` (48 bytes) - Successfully decrypted DPAPI blob
  - Hex: 1ce9ff4c9a63252a11a09e9b04dbaf10c28d604f06df3bc2017818370809b3678cd13436ee958a7f1e41d5cf70f7e5da
  - Source: Zoom.us.ini DPAPI blob decrypted with master key
  
- `ciphered_password.bin` (48 bytes) - Extracted from .zenc file
  - Hex: 834b7925662c9a8f749a96e6f1b16e0a1ff76e7a1d5ab2bb851a3f770662d453a7381ed5d7f8661586f14d528e5ea41a
  - Decrypted value: 4d255115e9dd08935374e77753997cb958d68e6ed56992c638ed9772edae2e1d4d241f095c1897364ddb9b8f91a8bf47
  
- `dpapi_blob.bin` (262 bytes) - DPAPI blob extracted from Zoom.us.ini
  - Master Key GUID: d2e8e6c0-b196-48ce-b4f3-60a4c99ab7f4
  
- `masterkey_at_*.bin` (31 files, 64 bytes each) - Master keys extracted from memory
  - Successfully used to decrypt DPAPI blob
  - Extracted from memory.raw at various offsets

## Working Scripts
- `decrypt_dpapi.py` - DPAPI blob decryption using dpapick3
- `decrypt_ciphered_password.py` - Decrypts CipheredPassword field from .zenc
- `run_dpapi_decrypt.py` - Working DPAPI decryption with conda environment

## Utility Files
- `zoom_memory_strings.txt` - Extracted strings from Zoom process memory
- `nt_hash.txt` - NT hash for user a1l4m

## Key Findings
1. Successfully decrypted DPAPI blob from Zoom.us.ini ✅
2. Successfully decrypted CipheredPassword from .zenc file ✅
3. Cannot decrypt LoggerInfo from .zenc file ❌
4. Cannot unlock SQLCipher database (zoomus.enc.db) ❌
5. User password not crackable with standard wordlists ❌

## Blockers
- Meeting ID and duration are inside encrypted database/logs
- Password required to unlock SQLCipher database
- LoggerInfo decryption method unknown
- NT hash c8e9430ee9a1f04828e2214ed538c20b not crackable

## Next Investigator Notes
- All DPAPI decryption completed successfully
- Need to find alternative method to decrypt LoggerInfo or SQLCipher database
- Consider reverse engineering Zoom client binary
- May require finding password through undiscovered clue
- Challenge has 0 solves - likely requires specialized knowledge
