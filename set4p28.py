#! /usr/bin/env python3

"""Implement a SHA-1 keyed MAC

Find a SHA-1 implementation in the language you code in.

Don't cheat. It won't work.

Do not use the SHA-1 implementation your language already provides
(for instance, don't use the "Digest" library in Ruby, or call
OpenSSL; in Ruby, you'd want a pure-Ruby SHA-1).

Write a function to authenticate a message under a secret key by using
a secret-prefix MAC, which is simply:

SHA1(key || message)

Verify that you cannot tamper with the message without breaking the
MAC you've produced, and that you can't produce a new MAC without
knowing the secret key.
"""

import os

import sha1

from set1 import b2h

def SHA1_prefix_MAC(key, message):
    h = sha1.Sha1Hash()
    h.update(key + message)
    return h.digest()

def SHA1_prefix_MAC_check(key, message, mac):
    expected_mac = SHA1_prefix_MAC(key, message)
    return expected_mac == mac

if __name__ == '__main__':
    print("Problem 28")
    key = os.urandom(8)
    message = b'Frog blast the vent core'
    mac = SHA1_prefix_MAC(key, message)
    print(message, b2h(mac), '-> OK:',
          SHA1_prefix_MAC_check(key, message, mac))
    forged_message = b' Dog blast the rent vore'
    print(forged_message, b2h(mac), '-> OK:',
          SHA1_prefix_MAC_check(key, forged_message, mac))
    assert not SHA1_prefix_MAC_check(key, forged_message, mac)
    print('Seems legit')
    print()

    
