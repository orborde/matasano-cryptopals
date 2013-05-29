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
    """Converts a hex string to a byte array. bytes.fromhex for
    Not-Invented-Here victims.
    """
    assert(len(s)%2 == 0)
    # Divide into 2-char chunks and convert to hex!
    return bytearray(int(''.join(chunk), 16) for chunk in grouper(2, s))

def b2h(b):
    """Converts a byte array to a hex string representation."""
    return ''.join(hex(x)[2:].zfill(2) for x in b)

# Alphabet from http://tools.ietf.org/html/rfc4648#section-4
B64_LOOKUP = ''.join(
    [chr(ord('A') + i) for i in range(26)] +
    [chr(ord('a') + i) for i in range(26)] +
    [chr(ord('0') + i) for i in range(10)]) + '+/'
# Used for quickish sanity checking in b642b validation. Yes, this
# could be faster. Premature optimization is great.
B64_CHARSET = set(B64_LOOKUP)

# TODO: fuck it :-)
import base64

# Extra test vectors from http://tools.ietf.org/html/rfc4648#section-10
def b2b64(input_bytedata):
    """bytes object -> b64 string.
    
    >>> OUTPUT_1 == b2b64(h2b(INPUT_1))
    True
    >>> b2b64(b'')
    ''
    >>> b2b64(b'f')
    'Zg=='
    >>> b2b64(b'fo')
    'Zm8='
    >>> b2b64(b'foo')
    'Zm9v'
    >>> b2b64(b'foob')
    'Zm9vYg=='
    >>> b2b64(b'fooba')
    'Zm9vYmE='
    >>> b2b64(b'foobar')
    'Zm9vYmFy'
    """
    # TODO: make this work right
    return base64.b64encode(input_bytedata).decode()

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
        # Mask out, look up, and output each 6-bit block.
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
        print('Going the extra mile')
        b64_length += 1
    print(len(input_bytedata), 'bytes encode to', b64_length, 'chars')
    print((b64_length*8) % 6)
    
    return ''.join(output[:b64_length])


def b642b(input_str):
    """Decode a base64 string to a bytes object.
    
    >>> b642b(b2b64(b'hello'))
    b'hello'
    """
    # TODO: make work for real
    return base64.b64decode(input_str.encode())
    
    # Make sure we have a valid base64 string!
    assert(all(c in B64_CHARSET for c in input_str))
    
    # Zero-pad until we have a string representing an integer number of
    # bytes. This saves some extra checking later.
    while (len(input_str) % 4):
        input_str += B64_LOOKUP[0]

    # TODO: compute a reverse lookup table!
    # Work in groups of 4 chars (3 bytes), letting us work a block at a time.
    output = bytearray()
    for group in grouper(4, input_str):
        ai, bi, ci, di = [B64_LOOKUP.index(x) for x in group]
        # Merge into a single integer
        piece = (ai << 18) + (bi << 12) + (ci << 6) + di
        print('NEXT BLOCK:', ai,bi,ci,di, piece)
        # Mask out and output each 8-bit block.
        for right_shift in [16, 8, 0]:
            bin_byte = (piece >> right_shift) & 0xFF
            print(piece >> right_shift, piece >> right_shift & 0xFF, bin_byte, chr(bin_byte))
            output.append(bin_byte)

    # Based on the input length, calculate how many bytes were in the
    # input byte vector, and trim down the output.
    #
    # (implemented, of course, with integer math to prevent all possible
    # floating point math mistakes)
    #
    # bin_length = math.floor(len(input_bytedata)*6/8)
    bin_length = (len(input_str)*6)//8
    return bytes(output[:bin_length])
  
def run_p1():
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

def run_p2():
    print('Problem 2')
    print('XORing')
    print(INPUT_2A)
    print('with')
    print(INPUT_2B)
    print('Expected output:', OUTPUT_2)
    print('Actual output:  ', b2h(xorvec(h2b(INPUT_2A), h2b(INPUT_2B))))
    print()

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

"""

def xorchar(char, vec):
    """XORs a single byte (int 0-255) against an entire byte array."""
    # Kind of a silly way of doing this, but why write more for loops
    # when you can use the one you already wrote?
    return xorvec(bytes([char]*len(vec)), vec)

INPUT_3 = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

DICT='/usr/share/dict/words'
print('Loading', DICT, 'for an English language model...')
words = set()
with open(DICT, 'r') as f:
    for l in f:
      word = l.strip().lower()
      if len(word) > 1:
        words.add(word)
print ('...dictionary loaded.', len(words), 'words')


def english_words_metric(vec):
    """Estimates how Englishy the UTF-8 decoding of 'vec' is.

    Score is how many of the characters [a-zA-Z'] can be decoded to
    dictionary words of length > 1, divided by the length of the
    string. Prior to attempting to decode words, all characters
    besides letters and apostrophes are replaced with spaces.
    """
    try:
      vec = vec.decode()
    except UnicodeDecodeError:
      return 0
    vec2 = []
    for c in vec:
        if c.isalpha() or c == "'":
            vec2.append(c)
        else:
            vec2.append(' ')
    vec = ''.join(vec2)
    wordvec = vec.split()
    words_found = [w for w in wordvec if (w in words)]
    score = sum(len(w) for w in words_found)
    return score / float(len(vec))


def crack_xorchar(vec):
    """Attempts to crack the xorchar "encryption" applied to byte array 'vec'"""
    decrypts = [(c, xorchar(c, vec)) for c in range(256)]
    return decrypts

def run_p3():
    decrypts = crack_xorchar(h2b(INPUT_3))
    decrypts.sort(key=lambda t: english_words_metric(t[1]))
    decrypts.reverse()

    k, t = decrypts[0]
    print('Problem 3')
    print('Best key is:', k)
    print('Best plaintext is:', t.decode())


"""
// ------------------------------------------------------------

4. Detect single-character XOR

One of the 60-character strings at:

  https://gist.github.com/3132713

has been encrypted by single-character XOR. Find it. (Your code from
#3 should help.)
"""

INPUT_4 = [l.strip() for l in open('set1p4.txt') if l.strip()]

def run_p4():
    print()
    print('Problem 4')
    possibilities = []
    for i in range(len(INPUT_4)):
        ctext = INPUT_4[i]
        decrypts = crack_xorchar(h2b(ctext))
        decrypts = [(english_words_metric(d), i, k, d) for k, d in decrypts]
        possibilities.extend(decrypts)

    # Sort by english_words_metric meaningfulness.
    possibilities.sort()
    possibilities.reverse()

    # I used this for debugging. Turns out the top answer won. How convenient!
    #for p in possibilities[:5]:
    #    print(p)

    _, i, k, d = possibilities[0]
    print('Best decrypt was on line', i+1, 'with key =', k)
    print('Plaintext:', d.decode())


"""
// ------------------------------------------------------------

5. Repeating-key XOR Cipher

Write the code to encrypt the string:

  Burning 'em, if you ain't quick and nimble
  I go crazy when I hear a cymbal

Under the key "ICE", using repeating-key XOR. It should come out to:

  0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f

Encrypt a bunch of stuff using your repeating-key XOR function. Get a
feel for it.
"""

INPUT_5 = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
KEY_5 = "ICE"
OUTPUT_5 = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

# Just to make sure I clipped the input string correctly.
assert(len(INPUT_5) * 2 == len(OUTPUT_5))

def xorbytes(key, vec):
    key_repeats = len(vec) // len(key) + 1  # approximately :-)
    key_vec = (key * key_repeats)[:len(vec)]
    return xorvec(key_vec, vec)

def run_p5():
    print('Encoding ASCII string', repr(INPUT_5), 'with key', repr(KEY_5))
    #print('Decoded expected output:',
    #      repr(xorbytes(KEY_5.encode(), h2b(OUTPUT_5))))
    print('Expected output:', OUTPUT_5)
    output = b2h(xorbytes(KEY_5.encode(), INPUT_5.encode()))
    print('Actual output:  ', output)
    assert(output == OUTPUT_5)


"""
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
"""

def bytes2binary(bytearr):
    """
    >>> bytes2binary(bytes([120, 10, 2]))
    '011110000000101000000010'
    """
    return ''.join(bin(b)[2:].zfill(8) for b in bytearr)

def hamming_distance(a, b):
    """
    >>> hamming_distance(b'this is a test', b'wokka wokka!!!')
    37
    """
    assert(len(a) == len(b))
    diff = bytes2binary(xorvec(a, b))
    return diff.count("1")

INPUT_6 = open('set1p6.txt').read()
def run_p6():
    gibberish = b642b(INPUT_6)
    # Run the Hamming autocorrelations by length
    candidates = []
    for length in range(1,len(gibberish)//2):
        # Chop up into groups. Drop the last one.
        reduced_length = (len(gibberish) // length) * length
        groups = list(grouper(length, gibberish[:reduced_length]))
        pairs = zip(groups[:-1], groups[1:])
        norm_distances = [hamming_distance(a,b)/length for a,b in pairs]
        avg_dist = sum(norm_distances) / len(norm_distances)
        print(length, avg_dist, len(gibberish) / length)
        candidates.append((avg_dist, length))
    candidates.sort()
    candidates.reverse()
    print('Top five!')
    for score, length in candidates[:5]:
        print(length, score)

# Because cheating is a great way to debug.
# (Turns out this did not actually find the key)
def dictionary_attack_p6():
    gibberish = b642b(INPUT_6)
    def enhanced_words():
        for word in words:
            if len(word) != 6:
                continue
            yield word
            yield word.upper()
            yield word.lower()
    my_dict = list(enhanced_words())
    print(len(my_dict), 'filtered words')
    decrypts = [(word, xorbytes(word.encode(), gibberish))
                for word in my_dict]
    decrypts.sort(key=lambda t: english_words_metric(t[1]))
    decrypts.reverse()
    for word, decrypt in decrypts[:5]:
        print(word, decrypt[:60])

"""
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
    if doctest.testmod()[0] == 0:
        #run_p1()
        #run_p2()
        #run_p3()
        #run_p4()
        #run_p5()
        #dictionary_attack_p6()  # that totally did not work
        run_p6()
