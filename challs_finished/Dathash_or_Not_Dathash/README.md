# Dathash or Not Dathash

**Challenge Name:** Dathash or Not Dathash
**Category:** Crypto
**Difficulty:** Easy
**Start Time:** 2025-11-20
**Status:** ✅ SOLVED

## Description
Deeper within the temple's vaults, Rei finds three mirrored tablets inscribed with divine equations—each claiming to reflect the same truth. Yet the air around them warps with faint echoes, as if reality itself trembles at their alignment. The monks once used these relics to test the nature of authenticity, but none remember which mirror held the real reflection.

## Challenge Details
- Challenge ID: 63300
- Flag ID: 783555
- Instance Type: TCP
- Points: 1000
- Solves: 1 (at time of solving)

## Solution Summary

This challenge exploits **Håstad's Broadcast Attack** combined with **Coppersmith's Method** to break RSA encryption with:
- Small exponent (e = 3)
- Three ciphertexts with linearly related messages
- Different moduli for each ciphertext

The flag was recovered using Chinese Remainder Theorem to combine the three polynomial equations, then applying Coppersmith's small_roots algorithm.

## Flag
```
HTB{h0w_t0_c0mb1n3_h4574d_b04rdc457_4nd_c0pp3rsm17h_4774ck}
```

## Files
- [WRITEUP.md](WRITEUP.md) - Detailed writeup with mathematical explanation
- [solution.sage](solution.sage) - Complete SageMath solution script
- [crypto_dathash_or_not_dathash/](crypto_dathash_or_not_dathash/) - Challenge files
