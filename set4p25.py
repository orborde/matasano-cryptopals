#!/usr/bin/env python3

"""Break "random access read/write" AES CTR

Back to CTR. Encrypt the recovered plaintext from this file (the ECB
exercise) under CTR with a random key (for this exercise the key
should be unknown to you, but hold on to it).

Now, write the code that allows you to "seek" into the ciphertext,
decrypt, and re-encrypt with different plaintext. Expose this as a
function, like, "edit(ciphertext, key, offset, newtext)".

Imagine the "edit" function was exposed to attackers by means of an
API call that didn't reveal the key or the original plaintext; the
attacker has the ciphertext and controls the offset and "new text".

Recover the original plaintext.

Food for thought:

A folkloric supposed benefit of CTR mode is the ability to easily
"seek forward" into the ciphertext; to access byte N of the
ciphertext, all you need to be able to do is generate byte N of the
keystream. Imagine if you'd relied on that advice to, say, encrypt a
disk.
"""

import os

from set1 import xorvec

import AES128

class RandomAccess:
    def __init__(self, plaintext):
        self._key = AES128.gen_key()
        self._nonce = AES128.CTR_gen_nonce()
        self._data = bytes([0] * len(plaintext))
        self.edit(0, plaintext)

    def edit(self, offset, data):
        startblock = offset // AES128.BLOCKSIZE
        endblock   = (offset + len(data)) // AES128.BLOCKSIZE
        keystream_blocks = [
            AES128.CTR_block(self._key, self._nonce, n)
            for n in range(startblock, endblock + 1)]
        keystream = b''.join(keystream_blocks)
        block_offset = offset % AES128.BLOCKSIZE
        keystream = keystream[block_offset:]
        keystream = keystream[:len(data)]
        new_ciphertext = xorvec(keystream, data)
        start_size = len(self._data)
        self._data = (
            self._data[:offset] +
            new_ciphertext +
            self._data[offset+len(data):])
        assert len(self._data) == start_size

    def leak_ciphertext(self):
        return self._data

def attack(edit, read_ciphertext):
    ciphertext = read_ciphertext()
    zeros = bytes([0] * len(ciphertext))
    edit(0, zeros)
    zerotext = read_ciphertext()
    keystream = zerotext
    plaintext = xorvec(keystream, ciphertext)
    edit(0, plaintext)
    return plaintext

if __name__ == '__main__':
    print('Problem 25')
    print('Setting up storage')
    plaintext = open('set1p7.plaintext', 'rb').read()
    RA = RandomAccess(plaintext)
    print("Here is some ciphertext (let's make sure we maybe encrypted)")
    print(RA.leak_ciphertext()[:20])
    print('Attacking!')
    recovered_plaintext = attack(RA.edit, RA.leak_ciphertext)
    assert recovered_plaintext == plaintext
    print('Success!')
    print(recovered_plaintext.splitlines()[0])

