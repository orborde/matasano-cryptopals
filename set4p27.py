#!/usr/bin/env python3

"""Recover the key from CBC with IV=Key

Take your code from the CBC exercise and modify it so that it
repurposes the key for CBC encryption as the IV.

Applications sometimes use the key as an IV on the auspices that both
the sender and the receiver have to know the key already, and can save
some space by using it as both a key and an IV.

Using the key as an IV is insecure; an attacker that can modify
ciphertext in flight can get the receiver to decrypt a value that will
reveal the key.

The CBC code from exercise 16 encrypts a URL string. Verify each byte
of the plaintext for ASCII compliance (ie, look for high-ASCII
values). Noncompliant messages should raise an exception or return an
error that includes the decrypted plaintext (this happens all the time
in real systems, for what it's worth).

Use your code to encrypt a message that is at least 3 blocks long:

AES-CBC(P_1, P_2, P_3) -> C_1, C_2, C_3

Modify the message (you are now the attacker):

C_1, C_2, C_3 -> C_1, 0, C_1

Decrypt the message (you are now the receiver) and raise the
appropriate error if high-ASCII is found.

As the attacker, recovering the plaintext from the error, extract the
key:

P'_1 XOR P'_3
"""

import os

import AES128
import util

from set1 import b2h, xorvec
from set2 import pkcs7pad, pkcs7unpad

KEY = AES128.gen_key()
IV  = KEY   # fffffuuuuuuu

def encrypt(msg):
    return AES128.CBC_encrypt(msg, KEY, IV)

def decrypt(ciphertext):
    return AES128.CBC_decrypt(ciphertext, KEY, IV)

def isascii(data):
    """
    >>> isascii(bytes([0xff, 0x13]))
    False
    >>> isascii(b'hello bob')
    True
    """
    return all(c < 128 for c in data)

def report_error(ciphertext):
    data = decrypt(ciphertext)
    if isascii(data):
        return None
    return data

PLAINTEXT = os.urandom(AES128.BLOCKSIZE * 3)
CIPHERTEXT = encrypt(PLAINTEXT)

def attack(report_error):
    C = [bytes(t) for t in util.grouper(AES128.BLOCKSIZE, CIPHERTEXT)]
    submission = C[0] + b'\0'*AES128.BLOCKSIZE + C[0]
    error = report_error(submission)
    assert error is not None
    Pnew = [bytes(t) for t in util.grouper(AES128.BLOCKSIZE, error)]
    key = xorvec(Pnew[0], Pnew[2])
    return key

import doctest
def load_tests(loader, tests, ignore):
    tests.addTests(doctest.DocTestSuite())
    return tests

if __name__ == '__main__':
    print('Problem 27')
    print('Attacking...')
    derived_key = attack(report_error)
    print('Original key :', b2h(KEY))
    print('Recovered key:', b2h(derived_key))
    assert KEY == derived_key
    print('Success!')
    print()
