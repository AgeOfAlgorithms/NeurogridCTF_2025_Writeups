# Elliptic Contribution - Writeup

**Challenge:** Elliptic Contribution
**Category:** Crypto
**Difficulty:** Very Easy
**Points:** 1000
**Flag:** `HTB{___sm4ll_0rd3r_c4us3s_r3p34t3d_0utputs____47e61b371f1683817d087504967ca5f0}`

## Summary

This challenge involved exploiting a weak elliptic curve with a composite order containing small factors. By performing a small subgroup attack, we recovered the secret key used for AES encryption.

## Vulnerability

The elliptic curve used in this challenge has order with small prime factors:
- Order = 1333357 × 14395288004057 × 32483634978817689715459 × 92622900837938235388817362484231041

The server accepts user-provided "offerings" (integers) that are converted to points on the curve and then multiplied by a secret scalar `x`. The x-coordinate of the resulting point is used as an AES key to encrypt the flag.

## Exploit

### Step 1: Discover Curve Parameters

- Obtained sample points from the server
- Used GCD of (y² - x³ - ax - b) values to find p
- Found: `p = 0x7fad2d5ec5d28f0acf09bdc1d2e663ec78c6473858e34191e12c37fc25b8dd39`
- Curve parameters a and b were given in server.py

### Step 2: Factor Curve Order

- Computed the order of the elliptic curve
- Factored it to find small subgroups
- Smallest factor: 1333357

### Step 3: Small Subgroup Attack

1. Generated a point G of order 1333357 on the curve
2. Sent G's x-coordinate as an "offering" to the server
3. Server computed G×x and used (G×x)[0] as AES key
4. Since G has order 1333357, only x mod 1333357 matters
5. Brute forced all 1,333,357 possibilities to find correct key
6. Found x mod 1333357 = 499560
7. Successfully decrypted the flag

## Key Insight

When an elliptic curve has a composite order with small factors, any point in a small-order subgroup will cycle through a limited number of outputs when multiplied by any scalar. This makes brute force attacks feasible.

## Flag

`HTB{___sm4ll_0rd3r_c4us3s_r3p34t3d_0utputs____47e61b371f1683817d087504967ca5f0}`
