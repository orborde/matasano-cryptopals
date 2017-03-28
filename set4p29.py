#! /usr/bin/env python3

"""Break a SHA-1 keyed MAC using length extension

Secret-prefix SHA-1 MACs are trivially breakable.

The attack on secret-prefix SHA1 relies on the fact that you can take
the ouput of SHA-1 and use it as a new starting point for SHA-1, thus
taking an arbitrary SHA-1 hash and "feeding it more data".

Since the key precedes the data in secret-prefix, any additional data
you feed the SHA-1 hash in this fashion will appear to have been
hashed with the secret key.

To carry out the attack, you'll need to account for the fact that
SHA-1 is "padded" with the bit-length of the message; your forged
message will need to include that padding. We call this "glue
padding". The final message you actually forge will be:

SHA1(key || original-message || glue-padding || new-message)

(where the final padding on the whole constructed message is implied)

Note that to generate the glue padding, you'll need to know the
original bit length of the message; the message itself is known to the
attacker, but the secret key isn't, so you'll need to guess at it.

This sounds more complicated than it is in practice.

To implement the attack, first write the function that computes the MD
padding of an arbitrary message and verify that you're generating the
same padding that your SHA-1 implementation is using. This should take
you 5-10 minutes.

Now, take the SHA-1 secret-prefix MAC of the message you want to forge
--- this is just a SHA-1 hash --- and break it into 32 bit SHA-1
registers (SHA-1 calls them "a", "b", "c", &c).

Modify your SHA-1 implementation so that callers can pass in new
values for "a", "b", "c" &c (they normally start at magic
numbers). With the registers "fixated", hash the additional data you
want to forge.

Using this attack, generate a secret-prefix MAC under a secret key
(choose a random word from /usr/share/dict/words or something) of the
string:

"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"

Forge a variant of this message that ends with ";admin=true".

This is a very useful attack.

For instance: Thai Duong and Juliano Rizzo, who got to this attack
before we did, used it to break the Flickr API."""

import os
import random
import struct

import sha1

from set1 import b2h
from set4p28 import *

def extend_mac(secret_key_length, original_message, mac, extension):
    print('Trying secret key length', secret_key_length)
    keymsg_length = secret_key_length + len(original_message)
    glue_padding = sha1.digest_suffix(keymsg_length)
    extended_message = (
        original_message +
        glue_padding +
        extension)
    # Set up as if the message processed so far is
    # original_message + glue_padding. The h vector is simply the
    # original MAC.
    sha = sha1.Sha1Hash()
    h = struct.unpack(b'>IIIII', mac)
    sha._h = h
    sha._message_byte_length = keymsg_length + len(glue_padding)
    sha.update(extension)
    ext_mac = sha.digest()
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
    mac = SHA1_prefix_MAC(key, message)
    print('ORIGINAL:', b2h(mac), message)
    assert SHA1_prefix_MAC_check(key, message, mac)
    extended_message, extended_mac = attack(
        message, mac, lambda msg,mac: SHA1_prefix_MAC_check(key, msg, mac))
    print('MODIFIED:', b2h(extended_mac), extended_message)
    assert SHA1_prefix_MAC_check(key, extended_message, extended_mac)
    assert EXTENSION in extended_message
    print("You're winner!")
    print()
