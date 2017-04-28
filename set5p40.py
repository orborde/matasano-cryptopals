#!/usr/bin/env python3

"""Implement an E=3 RSA Broadcast attack

Assume you're a Javascript programmer. That is, you're using a naive
handrolled RSA to encrypt without padding.

Assume you can be coerced into encrypting the same plaintext three
times, under three different public keys. You can; it's happened.

Then an attacker can trivially decrypt your message, by:

1. Capturing any 3 of the ciphertexts and their corresponding pubkeys

2. Using the CRT to solve for the number represented by the three
ciphertexts (which are residues mod their respective pubkeys)

3. Taking the cube root of the resulting number

The CRT says you can take any number and represent it as the
combination of a series of residues mod a series of moduli. In the
three-residue case, you have:

result =
  (c_0 * m_s_0 * invmod(m_s_0, n_0)) +
  (c_1 * m_s_1 * invmod(m_s_1, n_1)) +
  (c_2 * m_s_2 * invmod(m_s_2, n_2)) mod N_012

where:

 c_0, c_1, c_2 are the three respective residues mod
 n_0, n_1, n_2

 m_s_n (for n in 0, 1, 2) are the product of the moduli
 EXCEPT n_n --- ie, m_s_1 is n_0 * n_2

 N_012 is the product of all three moduli

To decrypt RSA using a simple cube root, leave off the final modulus
operation; just take the raw accumulated result and cube-root it."""

from set5p39 import *

SECRET = b"""
What's the word?
The word is the bird.
The word is a nerd.
Are you a curd?
Word.

Writing ridiculous plaintexts has to be one of the biggest challenges
of these exercises."""
KEYSIZE_BITS = 2048
assert len(SECRET)*8 < KEYSIZE_BITS

def vend_a_ciphertext():
    n, e, _ = gen_rsa(KEYSIZE_BITS)
    m = bytes2m(SECRET, n)
    c = rsa_encrypt(n, e, m)
    return c, n, e

# https://rosettacode.org/wiki/Integer_roots#Python
def iroot(a,b):
    if b<2:return b
    a1=a-1
    c=1
    d=(a1*c+b//(c**a1))//a
    e=(a1*d+b//(d**a1))//a
    while c!=d and c!=e:
        c,d,e=d,e,(a1*e+b//(e**a1))//a
    return min(d,e)

def attack(vend):
    vends = [vend() for _ in range(3)]
    c, n, e = (list(i) for i in zip(*vends))
    assert all(e == 3 for e in e)
    m_s = [
        n[1]*n[2],
        n[0]*n[2],
        n[0]*n[1]
    ]
    # I swear that I spent a while thinking about how to attack this
    # before I copy-pasted in this equation! :P
    result = util.crt_invert(n, c)
    # THE INSTRUCTIONS ARE FULL OF LIIIIIES.
    result = result % (n[0]*n[1]*n[2])
    m = iroot(3, result)
    for nv, cv in zip(n, c):
        assert (result % nv) == cv
    assert len(set((m % nv) for nv in n)) == 1
    return m2bytes(m)

if __name__ == '__main__':
    print('Problem 40')
    print('Secret:   ', SECRET)
    print('Attacking...')
    recovered = attack(vend_a_ciphertext)
    print('Recovered:', recovered)
    assert recovered == SECRET
    print('Success!')
    print()
