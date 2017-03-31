#!/usr/bin/env python3

"""Implement RSA

There are two annoying things about implementing RSA. Both of them
involve key generation; the actual encryption/decryption in RSA is
trivial.

First, you need to generate random primes. You can't just agree on a
prime ahead of time, like you do in DH. You can write this algorithm
yourself, but I just cheat and use OpenSSL's BN library to do the
work.

The second is that you need an "invmod" operation (the multiplicative
inverse), which is not an operation that is wired into your
language. The algorithm is just a couple lines, but I always lose an
hour getting it to work.

I recommend you not bother with primegen, but do take the time to get
your own EGCD and invmod algorithm working.

Now:

- Generate 2 random primes. We'll use small numbers to start, so you
  can just pick them out of a prime table. Call them "p" and "q".
- Let n be p * q. Your RSA math is modulo n.
- Let et be (p-1)*(q-1) (the "totient"). You need this value only for
  keygen.
- Let e be 3.
- Compute d = invmod(e, et). invmod(17, 3120) is 2753.
- Your public key is [e, n]. Your private key is [d, n].
- To encrypt: c = m**e%n. To decrypt: m = c**d%n
- Test this out with a number, like "42".
- Repeat with bignum primes (keep e=3).

Finally, to encrypt a string, do something cheesy, like convert the
string to hex and put "0x" on the front of it to turn it into a
number. The math cares not how stupidly you feed it strings."""

import subprocess

import doctest
def load_tests(loader, tests, ignore):
    tests.addTests(doctest.DocTestSuite())
    return tests

def genprime(bits):
    bits = int(bits)  # coerce for great justice
    cmd = ['openssl', 'prime', '-generate', '-bits', str(bits)]
    result = int(subprocess.check_output(cmd).strip())
    return result

def extended_gcd(a, b):
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = b, a
    while r != 0:
        quotient = old_r // r
        (old_r, r) = (r, old_r - quotient * r)
        (old_s, s) = (s, old_s - quotient * s)
        (old_t, t) = (t, old_t - quotient * t)
    return old_r, old_s, old_t, t, s

def invmod(x, mod):
    """Find the multiplicative inverse of 'x' mod 'mod'.

    >>> invmod(3, 5)
    2
    >>> invmod(17, 3120)
    2753
    """
    gcd, r, _, _, _ = extended_gcd(x, mod)
    if gcd == 1:
        return r % mod
    else:
        return None

import itertools
import unittest
class Invmod(unittest.TestCase):
    def test_lots(self):
        for x in range(1,101):
            for mod in range(x+1, 101):
                ix = invmod(x, mod)
                if ix is not None:
                    self.assertEqual((x*ix)%mod, 1)
