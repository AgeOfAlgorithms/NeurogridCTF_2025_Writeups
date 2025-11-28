# Dathash or Not Dathash - Writeup

**Challenge:** Dathash or Not Dathash
**Category:** Crypto
**Difficulty:** Easy
**Points:** 1000
**Solves:** 2 (at time of solving)

## Challenge Description

Deeper within the temple's vaults, Rei finds three mirrored tablets inscribed with divine equations—each claiming to reflect the same truth. Yet the air around them warps with faint echoes, as if reality itself trembles at their alignment. The monks once used these relics to test the nature of authenticity, but none remember which mirror held the real reflection.

## Provided Files

- `source.py` - The encryption script
- `output.txt` - Three sets of (n, c) pairs

## Analysis

### Understanding the Encryption

Looking at [source.py](crypto_dathash_or_not_dathash/source.py), we can see:

```python
class RSA:
    def __init__(self, bits):
        p = getPrime(bits//2)
        q = getPrime(bits//2)
        self.n = p * q
        assert isPrime(e - 1) and isPrime(e)
```

The key constraint is that **both `e` and `e-1` must be prime**. The only small value satisfying this is:
- **e = 3** (since 3 is prime and 2 is prime)

The encryption process creates three ciphertexts with related messages:

```python
for i in range(3):
    rsa = RSA(2048)
    c = rsa.encrypt(m := m + 2**2025)
```

This means:
- c₀ = (m₀ + 2²⁰²⁵)³ mod n₀
- c₁ = (m₀ + 2·2²⁰²⁵)³ mod n₁
- c₂ = (m₀ + 3·2²⁰²⁵)³ mod n₂

Where m₀ is the original message (FLAG + padding), approximately 1500 bits.

### The Vulnerability

This is a variant of **Håstad's Broadcast Attack** with **linear padding**. The attack combines:

1. **Håstad's Broadcast Attack**: When the same message is encrypted with e=3 using three different moduli, we can use the Chinese Remainder Theorem (CRT) to recover the message
2. **Coppersmith's Method**: Even with linear padding applied to each message, we can still recover the original message using Coppersmith's small roots algorithm

The key insight: Even though each message has a different linear offset (delta, 2·delta, 3·delta), we can construct a combined polynomial modulo N = n₀·n₁·n₂ that has m₀ as a small root.

## Solution

### Step 1: Setup the Polynomials

For each ciphertext, we create a polynomial that equals zero at m₀:
- g₀(x) = (x + δ)³ - c₀ ≡ 0 (mod n₀)
- g₁(x) = (x + 2δ)³ - c₁ ≡ 0 (mod n₁)
- g₂(x) = (x + 3δ)³ - c₂ ≡ 0 (mod n₂)

Where δ = 2²⁰²⁵.

### Step 2: Combine Using Chinese Remainder Theorem

We use CRT to combine these three congruences into a single polynomial modulo N = n₀·n₁·n₂:

```python
N = n0 * n1 * n2
N0 = N // n0
N1 = N // n1
N2 = N // n2

u0 = inverse_mod(N0 % n0, n0)
u1 = inverse_mod(N1 % n1, n1)
u2 = inverse_mod(N2 % n2, n2)

g = g0 * N0 * u0 + g1 * N1 * u1 + g2 * N2 * u2
```

The combined polynomial g(x) ≡ 0 (mod N) when x = m₀.

### Step 3: Apply Coppersmith's Method

Since m₀ ≈ 2¹⁵⁰⁰ is much smaller than N^(1/3) ≈ 2²⁰⁴⁷, we can use Coppersmith's small_roots() method to find m₀:

```python
PR_N = PolynomialRing(Zmod(N), 'x')
x_N = PR_N.gen()
f_N = PR_N(g)

X = 2^1550  # Upper bound on m0
roots = f_N.small_roots(X=X, beta=1.0, epsilon=1/30)

m0 = Integer(roots[0])
```

### Step 4: Decode the Flag

Convert m₀ to bytes and extract the flag:

```python
m0_bytes = m0.digits(256)
m0_bytes.reverse()
plaintext = bytes(m0_bytes)

# Extract flag
flag_start = plaintext.index(b'HTB{')
flag_end = plaintext.index(b'}', flag_start) + 1
flag = plaintext[flag_start:flag_end]
```

## Flag

```
HTB{h0w_t0_c0mb1n3_h4574d_b04rdc457_4nd_c0pp3rsm17h_4774ck}
```

## Key Takeaways

1. **Small exponents are dangerous**: Using e=3 makes RSA vulnerable to various attacks
2. **Linear padding doesn't help**: Håstad proved that applying linear transformations to messages doesn't prevent broadcast attacks
3. **Related messages are risky**: Encrypting related messages with the same small exponent across different keys allows reconstruction
4. **Proper padding is essential**: Modern RSA should use OAEP or similar padding schemes, not simple linear transformations

## Tools Used

- SageMath - For polynomial operations and Coppersmith's method
- Python - For data processing and conversion

## References

- [Håstad's Broadcast Attack](https://en.wikipedia.org/wiki/Coppersmith%27s_attack)
- [Coppersmith's Method](https://en.wikipedia.org/wiki/Coppersmith_method)
- [RSA with Small Exponent](https://crypto.stanford.edu/~dabo/pubs/papers/RSA-survey.pdf)
