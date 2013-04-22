#!/usr/bin/env python3

"""
// ------------------------------------------------------------

1. Convert hex to base64 and back.

The string:

  49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d

should produce:

  SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t

Now use this code everywhere for the rest of the exercises. Here's a
simple rule of thumb:

  Always operate on raw bytes, never on encoded strings. Only use hex
  and base64 for pretty-printing.

// ------------------------------------------------------------
"""

INPUT_1 = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
OUTPUT_1 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

import doctest
import itertools

# I'm learning Py3 as I go here. I see that this ridiculous hack is
# still necessary...
# http://stackoverflow.com/questions/5850536/how-to-chunk-a-list-in-python-3
def grouper(n, iterable, padvalue=None):
  "grouper(3, 'abcdefg', 'x') --> ('a','b','c'), ('d','e','f'), ('g','x','x')"
  return itertools.zip_longest(*[iter(iterable)]*n, fillvalue=padvalue)

def h2b(s):
    """Converts a hex string to a byte array."""
    assert(len(s)%2 == 0)
    # Divide into 2-char chunks and convert to hex!
    return bytearray(int(''.join(chunk), 16) for chunk in grouper(2, s))

def b2h(b):
    """Converts a byte array to a hex string representation."""
    return ''.join(hex(x)[2:] for x in b)

B64_LOOKUP = ''.join(
    [chr(ord('A') + i) for i in range(26)] +
    [chr(ord('a') + i) for i in range(26)] +
    [chr(ord('0') + i) for i in range(10)]) + '+/'
def b2b64(input_bytedata):
    """bytes object -> b64 string.
    
    >>> OUTPUT_1 == b2b64(h2b(INPUT_1))
    True
    """
    # Gah, I remember how much of a pain this was now.

    # Zero-pad. This saves writing some extra checking later.
    # 3 bytes -> 24 bits -> 4 6bit chunks
    # Therefore, pad out to a multiple of 3 bytes.
    bytedata = input_bytedata
    while len(bytedata) % 3:
        bytedata = bytedata + bytes(1)

    # Work in groups of 3 bytes, which lets us do a pretty simple
    # mask-and-shift loop.
    output = []
    for a,b,c in grouper(3, bytedata):
        # Merge into a big ol' int
        piece = (a << 16) + (b << 8) + c
        # Mask off the highest 6 bits, look up, and output. Do this 4
        # times (remember how we zero-padded?)
        for right_shift in [18, 12, 6, 0]:
            b64_byte = (piece >> right_shift) & 0x3F  # 0x3F = 0b00111111
            output.append(B64_LOOKUP[b64_byte])
    
    # So that we don't wind up with extraneous NULs on the end of the
    # decoded b64, calculate how many bytes of b64 are actually needed
    # to represent the original bytes, and trim the output to that.
    #
    # (The following is a gross misrepresentation of math.ceil(), but
    # it's done this way to make sure that the calculation is correct
    # in the face of any possible floating-point roundoff madness.)
    #
    # b64_length = math.ceil(len(input_bytedata)*8/6)
    b64_length = (len(input_bytedata)*8)//6
    if (b64_length*8) % 6:
        b64_length += 1
    
    return ''.join(output[:b64_length])

print('Problem 1')
print('Encoding hex string', INPUT_1)
print('Expected output:', OUTPUT_1)
print('Actual output:  ', b2b64(h2b(INPUT_1)))
print()

"""
2. Fixed XOR

Write a function that takes two equal-length buffers and produces
their XOR sum.

The string:

 1c0111001f010100061a024b53535009181c

... after hex decoding, when xor'd against:

 686974207468652062756c6c277320657965

... should produce:

 746865206b696420646f6e277420706c6179
"""

INPUT_2A = '1c0111001f010100061a024b53535009181c'
INPUT_2B = '686974207468652062756c6c277320657965'
OUTPUT_2 = '746865206b696420646f6e277420706c6179'

def xorvec(a, b):
    """XORs two bytes() objects together"""
    assert(len(a) == len(b))
    return bytes((x ^ y) for x,y in zip(a,b))

print('Problem 2')
print('XORing')
print(INPUT_2A)
print('with')
print(INPUT_2B)
print('Expected output:', OUTPUT_2)
print('Actual output:  ', b2h(xorvec(h2b(INPUT_2A), h2b(INPUT_2B))))

"""

// ------------------------------------------------------------

3. Single-character XOR Cipher

The hex encoded string:

      1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736

... has been XOR'd against a single character. Find the key, decrypt
the message.

Write code to do this for you. How? Devise some method for "scoring" a
piece of English plaintext. (Character frequency is a good metric.)
Evaluate each output and choose the one with the best score.

Tune your algorithm until this works.

// ------------------------------------------------------------

4. Detect single-character XOR

One of the 60-character strings at:

  https://gist.github.com/3132713

has been encrypted by single-character XOR. Find it. (Your code from
#3 should help.)

// ------------------------------------------------------------

5. Repeating-key XOR Cipher

Write the code to encrypt the string:

  Burning 'em, if you ain't quick and nimble
  I go crazy when I hear a cymbal

Under the key "ICE", using repeating-key XOR. It should come out to:

  0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f

Encrypt a bunch of stuff using your repeating-key XOR function. Get a
feel for it.

// ------------------------------------------------------------

6. Break repeating-key XOR

The buffer at the following location:

 https://gist.github.com/3132752

is base64-encoded repeating-key XOR. Break it.

Here's how:

a. Let KEYSIZE be the guessed length of the key; try values from 2 to
(say) 40.

b. Write a function to compute the edit distance/Hamming distance
between two strings. The Hamming distance is just the number of
differing bits. The distance between:

  this is a test

and:

  wokka wokka!!!

is 37.

c. For each KEYSIZE, take the FIRST KEYSIZE worth of bytes, and the
SECOND KEYSIZE worth of bytes, and find the edit distance between
them. Normalize this result by dividing by KEYSIZE.

d. The KEYSIZE with the smallest normalized edit distance is probably
the key. You could proceed perhaps with the smallest 2-3 KEYSIZE
values. Or take 4 KEYSIZE blocks instead of 2 and average the
distances.

e. Now that you probably know the KEYSIZE: break the ciphertext into
blocks of KEYSIZE length.

f. Now transpose the blocks: make a block that is the first byte of
every block, and a block that is the second byte of every block, and
so on.

g. Solve each block as if it was single-character XOR. You already
have code to do this.

e. For each block, the single-byte XOR key that produces the best
looking histogram is the repeating-key XOR key byte for that
block. Put them together and you have the key.

// ------------------------------------------------------------

7. AES in ECB Mode

The Base64-encoded content at the following location:

    https://gist.github.com/3132853

Has been encrypted via AES-128 in ECB mode under the key

    "YELLOW SUBMARINE".

(I like "YELLOW SUBMARINE" because it's exactly 16 bytes long).

Decrypt it.

Easiest way:

Use OpenSSL::Cipher and give it AES-128-ECB as the cipher.

// ------------------------------------------------------------

8. Detecting ECB

At the following URL are a bunch of hex-encoded ciphertexts:

   https://gist.github.com/3132928

One of them is ECB encrypted. Detect it.

Remember that the problem with ECB is that it is stateless and
deterministic; the same 16 byte plaintext block will always produce
the same 16 byte ciphertext.

// ------------------------------------------------------------
"""



if __name__=='__main__':
    doctest.testmod()
