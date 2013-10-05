#! /usr/bin/env python3

import doctest

"""
// ------------------------------------------------------------

17. The CBC padding oracle

Combine your padding code and your CBC code to write two functions.

The first function should select at random one of the following 10
strings:

MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93

generate a random AES key (which it should save for all future
encryptions), pad the string out to the 16-byte AES block size and
CBC-encrypt it under that key, providing the caller the ciphertext and
IV.

The second function should consume the ciphertext produced by the
first function, decrypt it, check its padding, and return true or
false depending on whether the padding is valid.

This pair of functions approximates AES-CBC encryption as its deployed
serverside in web applications; the second function models the
server's consumption of an encrypted session token, as if it was a
cookie.

It turns out that it's possible to decrypt the ciphertexts provided by
the first function.

The decryption here depends on a side-channel leak by the decryption
function.

The leak is the error message that the padding is valid or not.

You can find 100 web pages on how this attack works, so I won't
re-explain it. What I'll say is this:

The fundamental insight behind this attack is that the byte 01h is
valid padding, and occur in 1/256 trials of "randomized" plaintexts
produced by decrypting a tampered ciphertext.

02h in isolation is NOT valid padding.

02h 02h IS valid padding, but is much less likely to occur randomly
than 01h.

03h 03h 03h is even less likely.

So you can assume that if you corrupt a decryption AND it had valid
padding, you know what that padding byte is.

It is easy to get tripped up on the fact that CBC plaintexts are
"padded". Padding oracles have nothing to do with the actual padding
on a CBC plaintext. It's an attack that targets a specific bit of code
that handles decryption. You can mount a padding oracle on ANY CBC
block, whether it's padded or not.

"""

import os
import random

from set1 import b2b64, b642b, grouper, xorvec
from set2 import *

P17_PLAINTEXTS = map(b642b, [
        'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
        'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
        'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
        'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
        'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
        'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
        'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
        'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
        'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
        'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93'])

P17_KEY = os.urandom(KEYSIZE)

def p17_mysterytext():
    plaintext = random.choice(P17_PLAINTEXTS)
    return AES128_CBC_encrypt(pkcs7pad(plaintext), P17_KEY)

def p17_padding_oracle(ciphertext):
    padded = AES128_CBC_decrypt(ciphertext, P17_KEY)
    if pkcs7unpad_core(padded) is None:
        return False
    return True

def zero_prefix(data, size):
    return bytes(size - len(data)) + data

def zero_suffix(data, size):
    return data + bytes(size - len(data))

def padding_oracle_crack_block(oracle, prev_block, block):
    def crack_helper(index, known_part):
        # index: character that we're trying to deduce
        # known_part: the last (blocksize - index - 1) bytes of the block
        #   plaintext, which we should know at this point.

        # If we are trying to crack the 2nd byte of 16, we want 15
        # bytes of padding. The i'th byte corresponds to
        # index = (i - 1), and we happen to want
        # BLOCKSIZE - (i - 1) pad bytes. Very convenient.
        pad_char = BLOCKSIZE - index
        tamper_suffix_len = pad_char - 1
        assert(tamper_suffix_len + index + 1 == BLOCKSIZE)
        # Create a suffix to the tamper IV such that AES_decrypt(block) XOR
        # prev_block XOR tamper_iv will have a suffix of pad_char.
        #
        # K = padding character
        # D[i] = AES_decrypt(block)[i]
        # V[i] = prev_block[i]
        # P[i] = known_part[i]
        # T[i] = tamper_iv[i]
        #
        # We know that P[i] = V[i] ^ D[i]. We want D[i] ^ T[i] = K.
        # T[i] = K ^ D[i]
        # D[i] = P[i] ^ V[i] (yes, we could theoretically keep this around
        #   instead of recomputing it every time)
        # T[i] = K ^ P[i] ^ V[i]
        pad_suffix = bytes([pad_char] * tamper_suffix_len)
        if tamper_suffix_len > 0:
            tamper_iv_suffix = xorvec(pad_suffix,
                                      known_part[-tamper_suffix_len:],
                                      prev_block[-tamper_suffix_len:])
        else:
            tamper_iv_suffix = bytes()
        assert(len(tamper_iv_suffix) == pad_char - 1)
        # OK, now we look for tamper_iv[index] (let's call that 'T')
        # such that
        #
        # (tamper_iv^aes_decrypt(block))[index] == pad_char.
        #
        # We do that by finding a tamper_iv that results in
        # tamper_iv^aes_decrypt(block) being a block with valid
        # padding, and we do that using the padding oracle. There's a
        # wrinkle here, though; there are sometimes *two*
        # candidates. Consider the case where the target plaintext
        # ends with '\x02\x55'. Replacing 0x55 by either 0x01 *or*
        # 0x02 will produce a correctly padded block. However, the
        # tamper_iv[index] that produced 0x01 will (probably) at some
        # point lead us down a blind alley where we can not find the
        # next tamper_iv[index], and, at that point, we backtrack.
        #
        # TODO: eliminate the probabilistic element from the above.
        candidates = []
        for T in range(256):
            tamper_iv = zero_prefix(bytes([T]) + tamper_iv_suffix, BLOCKSIZE)
            if oracle(tamper_iv + block):
                candidates.append(T)
        # Now, remember, for each valid T,
        # T ^ AES_decrypt(block)[index] = pad_char
        # We want to recover the *actual* plaintext, which is:
        # plaintext_byte = prev_block[index] ^ AES_decrypt(block)[index]
        #                = prev_block[index] ^ T ^ pad_char
        candidates = [prev_block[index] ^ T ^ pad_char for T in candidates]
        return [bytes([c]) + known_part for c in candidates]

    assert(len(prev_block) == BLOCKSIZE)
    assert(len(block) == BLOCKSIZE)
    suffix_possibilities = [bytes()]
    for i in range(BLOCKSIZE):
        index = BLOCKSIZE - i - 1
        #print('Solving index', index)
        if len(suffix_possibilities) == 0:
            #print('No possibilities left!')
            break
        #print('Possibilities are:')
        new_suffix_possibilities = []
        for p in suffix_possibilities:
            adds = crack_helper(index, p)
            #print(p, '(expanded to', len(adds), 'possibilities)')
            new_suffix_possibilities.extend(adds)
        suffix_possibilities = new_suffix_possibilities
    return suffix_possibilities

def padding_oracle_crack(oracle, ciphertext):
    assert(len(ciphertext) % BLOCKSIZE == 0)
    data = bytearray()
    for i in range(0, len(ciphertext)//BLOCKSIZE - 1):
        prev_block = ciphertext[(i*BLOCKSIZE):((i+1)*BLOCKSIZE)]
        block = ciphertext[((i+1)*BLOCKSIZE):((i+2)*BLOCKSIZE)]
        candidates = padding_oracle_crack_block(oracle, prev_block, block)
        assert(len(candidates) == 1)
        data.extend(candidates[0])
    return data

P17_TEST_KEY = b'1234567890123456'
P17_TEST_IV = os.urandom(BLOCKSIZE)
P17_TEST_PLAINTEXT = b'moofy hollins eh'
P17_TEST_CIPHERTEXT = AES128_CBC_encrypt(
    P17_TEST_PLAINTEXT, P17_TEST_KEY, iv=P17_TEST_IV)
assert(P17_TEST_CIPHERTEXT[:BLOCKSIZE] == P17_TEST_IV)

def p17_test_oracle(ciphertext):
    assert(len(ciphertext) == 2*BLOCKSIZE)
    padded = AES128_CBC_decrypt(ciphertext, P17_TEST_KEY)
    if pkcs7unpad_core(padded) is None:
        return False
    #print('oracle decoded valid:', padded)
    return True

def run_p17():
    # Here's a stupid quick hack to make sure it's more-or-less working.
    assert(P17_TEST_PLAINTEXT ==
           padding_oracle_crack(p17_test_oracle, P17_TEST_CIPHERTEXT))

run_p17()

"""
// ------------------------------------------------------------

18. Implement CTR mode

The string:

    L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==

decrypts to something approximating English in CTR mode, which is an
AES block cipher mode that turns AES into a stream cipher, with the
following parameters:

          key=YELLOW SUBMARINE
          nonce=0
          format=64 bit unsigned little endian nonce,
                 64 bit little endian block count (byte count / 16)

CTR mode is very simple.

Instead of encrypting the plaintext, CTR mode encrypts a running
counter, producing a 16 byte block of keystream, which is XOR'd
against the plaintext.

For instance, for the first 16 bytes of a message with these
parameters:

    keystream = AES("YELLOW SUBMARINE",
                    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")

for the next 16 bytes:

    keystream = AES("YELLOW SUBMARINE",
                    "\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00")

and then:

    keystream = AES("YELLOW SUBMARINE",
                    "\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00")

CTR mode does not require padding; when you run out of plaintext, you
just stop XOR'ing keystream and stop generating keystream.

Decryption is identical to encryption. Generate the same keystream,
XOR, and recover the plaintext.

Decrypt the string at the top of this function, then use your CTR
function to encrypt and decrypt other things.

// ------------------------------------------------------------

19. Break fixed-nonce CTR mode using substitions

Take your CTR encrypt/decrypt function and fix its nonce value to
0. Generate a random AES key.

In SUCCESSIVE ENCRYPTIONS (NOT in one big running CTR stream), encrypt
each line of the base64 decodes of the following,
producing multiple independent ciphertexts:

   SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==
   Q29taW5nIHdpdGggdml2aWQgZmFjZXM=
   RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==
   RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=
   SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk
   T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
   T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=
   UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
   QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=
   T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl
   VG8gcGxlYXNlIGEgY29tcGFuaW9u
   QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==
   QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=
   QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==
   QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=
   QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=
   VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==
   SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==
   SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==
   VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==
   V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==
   V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==
   U2hlIHJvZGUgdG8gaGFycmllcnM/
   VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=
   QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=
   VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=
   V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=
   SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==
   U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==
   U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=
   VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==
   QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu
   SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=
   VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs
   WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=
   SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0
   SW4gdGhlIGNhc3VhbCBjb21lZHk7
   SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=
   VHJhbnNmb3JtZWQgdXR0ZXJseTo=
   QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=

(This should produce 40 short CTR-encrypted ciphertexts).

Because the CTR nonce wasn't randomized for each encryption, each
ciphertext has been encrypted against the same keystream. This is very
bad.

Understanding that, like most stream ciphers (including RC4, and
obviously any block cipher run in CTR mode), the actual "encryption"
of a byte of data boils down to a single XOR operation, it should be
plain that:

  CIPHERTEXT-BYTE XOR PLAINTEXT-BYTE = KEYSTREAM-BYTE

And since the keystream is the same for every ciphertext:

  CIPHERTEXT-BYTE XOR KEYSTREAM-BYTE = PLAINTEXT-BYTE (ie, "you don't
  say!")

Attack this cryptosystem "Carmen Sandiego" style: guess letters, use
expected English language frequence to validate guesses, catch common
English trigrams, and so on. Points for automating this, but part of
the reason I'm having you do this is that I think this approach is
suboptimal.

// ------------------------------------------------------------

20. Break fixed-nonce CTR mode using stream cipher analysis

At the following URL:

   https://gist.github.com/3336141

Find a similar set of Base64'd plaintext. Do with them exactly
what you did with the first, but solve the problem differently.

Instead of making spot guesses at to known plaintext, treat the
collection of ciphertexts the same way you would repeating-key
XOR.

Obviously, CTR encryption appears different from repeated-key XOR,
but with a fixed nonce they are effectively the same thing.

To exploit this: take your collection of ciphertexts and truncate
them to a common length (the length of the smallest ciphertext will
work).

Solve the resulting concatenation of ciphertexts as if for repeating-
key XOR, with a key size of the length of the ciphertext you XOR'd.

// ------------------------------------------------------------

21. Implement the MT19937 Mersenne Twister RNG

You can get the psuedocode for this from Wikipedia. If you're writing
in Python, Ruby, or (gah) PHP, your language is probably already
giving you MT19937 as "rand()"; don't use rand(). Write the RNG
yourself.

// ------------------------------------------------------------

22. "Crack" An MT19937 Seed

Make sure your MT19937 accepts an integer seed value. Test it (verify
that you're getting the same sequence of outputs given a seed).

Write a routine that performs the following operation:

* Wait a random number of seconds between, I don't know, 40 and 1000.

* Seeds the RNG with the current Unix timestamp

* Waits a random number of seconds again.

* Returns the first 32 bit output of the RNG.

You get the idea. Go get coffee while it runs. Or just simulate the
passage of time, although you're missing some of the fun of this
exercise if you do that.

From the 32 bit RNG output, discover the seed.

// ------------------------------------------------------------

23. Clone An MT19937 RNG From Its Output

The internal state of MT19937 consists of 624 32 bit integers.

For each batch of 624 outputs, MT permutes that internal state. By
permuting state regularly, MT19937 achieves a period of 2**19937,
which is Big.

Each time MT19937 is tapped, an element of its internal state is
subjected to a tempering function that diffuses bits through the
result.

The tempering function is invertible; you can write an "untemper"
function that takes an MT19937 output and transforms it back into the
corresponding element of the MT19937 state array.

To invert the temper transform, apply the inverse of each of the
operations in the temper transform in reverse order. There are two
kinds of operations in the temper transform each applied twice; one is
an XOR against a right-shifted value, and the other is an XOR against
a left-shifted value AND'd with a magic number. So you'll need code to
invert the "right" and the "left" operation.

Once you have "untemper" working, create a new MT19937 generator, tap
it for 624 outputs, untemper each of them to recreate the state of the
generator, and splice that state into a new instance of the MT19937
generator.

The new "spliced" generator should predict the values of the original.

How would you modify MT19937 to make this attack hard? What would
happen if you subjected each tempered output to a cryptographic hash?

// ------------------------------------------------------------

24. Create the MT19937 Stream Cipher And Break It

You can create a trivial stream cipher out of any PRNG; use it to
generate a sequence of 8 bit outputs and call those outputs a
keystream. XOR each byte of plaintext with each successive byte of
keystream.

Write the function that does this for MT19937 using a 16-bit
seed. Verify that you can encrypt and decrypt properly. This code
should look similar to your CTR code.

Use your function to encrypt a known plaintext (say, 14 consecutive
'A' characters) prefixed by a random number of random characters.

From the ciphertext, recover the "key" (the 16 bit seed).

Use the same idea to generate a random "password reset token" using
MT19937 seeded from the current time.

Write a function to check if any given password token is actually
the product of an MT19937 PRNG seeded with the current time.

"""
