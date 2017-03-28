#!/usr/bin/env python3

"""There are people in the world that believe that CTR resists bit
flipping attacks of the kind to which CBC mode is susceptible.

Re-implement the CBC bitflipping exercise from earlier (#16) to use
CTR mode instead of CBC mode. Inject an "admin=true" token.

"""

import AES128

from set1 import xorvec

KEY = AES128.gen_key()
PREFIX = b'comment1=cooking%20MCs;userdata='
SUFFIX = b';comment2=%20like%20a%20pound%20of%20bacon'

def cookie(userdata):
    """
    >>> print(cookie_decode(cookie(b'hello')).decode())
    comment1=cooking%20MCs;userdata=hello;comment2=%20like%20a%20pound%20of%20bacon
    >>> print(cookie_decode(cookie(b';admin=true;')).decode())
    comment1=cooking%20MCs;userdata=\;admin\=true\;;comment2=%20like%20a%20pound%20of%20bacon
    """
    # Sanitize
    userdata = userdata.replace(b';', b'\\;')
    userdata = userdata.replace(b'=', b'\\=')
    # And go!
    nonce = AES128.CTR_gen_nonce()
    data = (PREFIX + userdata + SUFFIX)
    ct = AES128.CTR_crypt(KEY, nonce, data)
    return nonce + ct

def cookie_decode(cookie):
    split = AES128.CTR_NONCE_SIZE
    nonce, data = cookie[:split], cookie[split:]
    return AES128.CTR_crypt(KEY, nonce, data)

def cookie_is_admin(cookie):
    return b';admin=true;' in cookie_decode(cookie)

import doctest
def load_tests(loader, tests, ignore):
    tests.addTests(doctest.DocTestSuite())
    return tests

TO_INJECT=b';admin=true;'
def attack(vend_cookie):
    mincookie = vend_cookie(b'')
    minlen = len(mincookie)
    # Make the user data long enough that we can definitely target our
    # injected data in it.
    landingpad = b'A' * minlen * 2
    lookycookie = vend_cookie(landingpad)
    splice_start, splice_end = minlen, minlen+len(TO_INJECT)
    segment = lookycookie[splice_start:splice_end]
    assert(len(segment) == len(TO_INJECT))
    landingpad_segment = b'A'*len(segment)
    segment_keystream = xorvec(landingpad_segment, segment)
    segment = xorvec(segment_keystream, TO_INJECT)
    atkkie = (lookycookie[:splice_start] +
              segment +
              lookycookie[splice_end:])
    assert len(atkkie) == len(lookycookie)
    return atkkie

if __name__ == '__main__':
    print("Problem 26")
    print("Attacking...")
    badcookie = attack(cookie)
    print("Attack cookie is:", badcookie)
    print("  which decodes to", cookie_decode(badcookie))
    assert cookie_is_admin(badcookie)
    print("Admin cookie generated!")
    print()
