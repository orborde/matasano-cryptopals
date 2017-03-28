#!/usr/bin/env python3

"""Break an MD4 keyed MAC using length extension

Second verse, same as the first, but use MD4 instead of SHA-1. Having
done this attack once against SHA-1, the MD4 variant should take much
less time; mostly just the time you'll spend Googling for an
implementation of MD4.

You're thinking, why did we bother with this?

Blame Stripe. In their second CTF game, the second-to-last challenge
involved breaking an H(k, m) MAC with SHA1. Which meant that SHA1 code
was floating all over the Internet. MD4 code, not so much."""

import os
import random
import struct

from set1 import b2h

import md4

def MD4_prefix_MAC(key, message):
    return bytes(md4.MD4(key + message))

def MD4_prefix_MAC_check(key, message, mac):
    expected_mac = MD4_prefix_MAC(key, message)
    return expected_mac == mac

def extend_mac(secret_key_length, original_message, mac, extension):
    print('Trying secret key length', secret_key_length)
    keymsg_length = secret_key_length + len(original_message)
    glue_padding = md4.md_pad_64(
        original_message,
        md4.MD4_length2bytes,
        fake_byte_len=keymsg_length)
    extended_message = (
        original_message +
        glue_padding +
        extension)
    # Set up as if the message processed so far is
    # original_message + glue_padding.
    state = struct.unpack(b'>IIII', mac)
    final_byte_count = (
        keymsg_length +
        len(glue_padding) +
        len(extension))
    ext_mac = bytes(md4.MD4(
        extension, fake_byte_len=final_byte_count, state=state))
    return extended_message, ext_mac

EXTENSION = b';admin=true;'
def attack(original_message, mac, validate):
    for secret_len in range(20+1):
        newmsg, newmac = extend_mac(
            secret_len, original_message, mac, EXTENSION)
        if validate(newmsg, newmac):
            return newmsg, newmac
    assert False, "No reasonably short secret key length worked"


if __name__ == '__main__':
    print('Problem 29')
    key = os.urandom(random.randint(8, 20))
    print('Key =', b2h(key))
    message = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    mac = MD4_prefix_MAC(key, message)
    print('ORIGINAL:', mac, b2h(mac), message)
    assert MD4_prefix_MAC_check(key, message, mac)
    extended_message, extended_mac = attack(
        message, mac, lambda msg,mac: MD4_prefix_MAC_check(key, msg, mac))
    print('MODIFIED:', b2h(extended_mac), extended_message)
    assert MD4_prefix_MAC_check(key, extended_message, extended_mac)
    assert EXTENSION in extended_message
    print("You're winner!")
    print()
