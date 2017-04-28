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

import util

def gen_rsa(bits):
    """Generate an RSA keypair with a modulus of (probably) size 'bits'."""
    e = 3
    p = genprime(bits // 2)
    q = genprime(bits // 2)
    n = p*q
    et = (p-1)*(q-1)
    d = util.invmod(e, et)
    return n, e, d

def powmod(x, p, m):
    """Computes x^p mod m efficiently.

    >>> powmod(2, 10, 11)
    1
    >>> powmod(2, 13, 11)
    8
    >>> powmod(0, 13, 11)
    0
    """
    if x == 0:
        return 0
    res = 1
    mul = x
    assert p >= 0
    while p > 0:
        b = p%2
        if b:
            res = (res * mul) % m
        p = p // 2
        mul = (mul * mul) % m
    return res

def rsa_encrypt(n, e, m):
    return powmod(m, e, n)
def rsa_decrypt(n, d, c):
    return powmod(c, d, n)

from set1 import b2h, h2b

def bytes2m(b, n):
    m = 0
    for x in b:
        m *= 256
        m += x
    assert m < n
    return m
def m2bytes(m):
    b = []
    assert m >= 0
    while m != 0:
        d = m % 256
        b.append(d)
        m = m >> 8
    b.reverse()
    return bytes(b)

if __name__ == '__main__':
    print('Problem 39')
    print('Generating some RSA keys')
    n, e, d = gen_rsa(2048)
    print('n =', n)
    print('e =', e)
    print('d =', d)

    message = (
        b'Bacon and a half wich, never more to go.\n' +
        b'Ever are ridiculous, for they are sure to flow.\n' +
        b'When did the cow taffer its way under the gate?\n' +
        b'Answer: when a good prognost went on a lovely date!')
    print('Encrypting', message)
    m = bytes2m(message, n)
    print('m =', m)
    c = rsa_encrypt(n, e, m)
    print('c =', c)
    p = rsa_decrypt(n, d, c)
    assert p == m
    pt = m2bytes(p)
    print('Decrypt is:', pt)
    assert pt == message
