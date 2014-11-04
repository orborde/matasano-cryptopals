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
    >>> b2b64(b'hello')
    'aGVsbG8='
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
    if (len(input_bytedata)*8) % 6:
        b64_length += 1
    b64 = ''.join(output[:b64_length])
    # Apply RFC-mandated padding
    while len(b64) % 4:
        b64 += '='
    return b64


def b642b(input_str):
    """Decode a base64 string to a bytes object.
    
    >>> b642b(b2b64(b'hello'))
    b'hello'
    """
    # Strip out whitespace
    input_str = ''.join(input_str.split())
    # Strip off padding from the end.
    input_str = input_str.rstrip('=')
    # Make sure we have a valid base64 string!
    assert(all(c in B64_CHARSET for c in input_str))

    # Save the original string length for proper result truncation later.
    input_str_len = len(input_str)
    
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
        # Mask out and output each 8-bit block.
        for right_shift in [16, 8, 0]:
            bin_byte = (piece >> right_shift) & 0xFF
            output.append(bin_byte)

    # Based on the input length, calculate how many bytes were in the
    # input byte vector, and trim down the output.
    #
    # (implemented, of course, with integer math to prevent all possible
    # floating point math mistakes)
    #
    # bin_length = math.floor(input_str_len)*6/8)
    bin_length = (input_str_len*6)//8
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

def xorvec_helper(a, b):
    assert(len(a) == len(b))
    return bytes((x ^ y) for x,y in zip(a,b))

def xorvec(*args):
    """XORs bytes() objects together"""
    output = args[0]
    for n in args[1:]:
        output = xorvec_helper(output, n)
    return output

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
#print('Loading', DICT, 'for an English language model...')
words = set()
with open(DICT, 'r') as f:
    for l in f:
        word = l.strip().lower()
        if len(word) > 1:
            words.add(word)
#print ('...dictionary loaded.', len(words), 'words')


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

# Frequency table cribbed from
# http://en.algoritmy.net/article/40379/Letter-frequency-English
ENGLISH_LETTER_FREQUENCIES=[
    ['A', '8.167'],
    ['B', '1.492'],
    ['C', '2.782'],
    ['D', '4.253'],
    ['E', '12.702'],
    ['F', '2.228'],
    ['G', '2.015'],
    ['H', '6.094'],
    ['I', '6.966'],
    ['J', '0.153'],
    ['K', '0.772'],
    ['L', '4.025'],
    ['M', '2.406'],
    ['N', '6.749'],
    ['O', '7.507'],
    ['P', '1.929'],
    ['Q', '0.095'],
    ['R', '5.987'],
    ['S', '6.327'],
    ['T', '9.056'],
    ['U', '2.758'],
    ['V', '0.978'],
    ['W', '2.360'],
    ['X', '0.150'],
    ['Y', '1.974'],
    ['Z', '0.074']
    ]
ENGLISH_LETTER_FREQUENCIES = dict(
    (letter.encode(), float(val)/100)
    for letter,val in ENGLISH_LETTER_FREQUENCIES)

def english_letters_metric(vec):
    """Score a candidate plaintext by the sum of the frequencies of
    its letters.
    """
    vec = vec.upper()
    valid_letters = bytearray(
        c for c in vec if (bytes([c]) in ENGLISH_LETTER_FREQUENCIES))
    if len(valid_letters) == 0:
        return 0
    score = (
        sum(ENGLISH_LETTER_FREQUENCIES[bytes([c])] for c in valid_letters))
    return score

import math

ENGLISH_LETTERS_LOG_FREQUENCIES = dict(
    (letter, math.log(val))
    for letter,val in ENGLISH_LETTER_FREQUENCIES.items())
def english_letters_log_metric(vec):
    """ TODO: Explain me. Multinomial distribution, logspace, yadda yadda. """
    vec = vec.upper()
    return sum(vec.count(letter) * val
               for letter,val in ENGLISH_LETTERS_LOG_FREQUENCIES.items())


#from fractions import Fraction

def load_english_bytes_frequencies():
    # Load the bytes histogram model and preprocess it so that it's useful for
    # scoring.
    counts = [0] * 256
    for line in open('histo.txt'):
        c, ct = map(int, line.split())
        counts[c] = ct

    # TODO: Try fractions if this doesn't work. Unfortunately, we'll probably
    # have to work around http://bugs.python.org/issue21136 to make it work
    # properly.
    total = sum(counts)
    frequencies = [float(ct)/ total for ct in counts]
    return frequencies
ENGLISH_BYTE_FREQUENCIES = load_english_bytes_frequencies()

def english_bytes_metric(vec):
    """Score a candidate plaintext by evaluating how likely it is, using a
    multinomial distribution model of bytes that happen to comprise English
    text.

    Well, sort of. It turns out that, in order to compare candidate decryptions
    of sets of bytes encrypted by a 1:1 mapping between input and output bytes
    (e.g. XOR against a key byte), it's kind of a waste of time to evaluate the
    mess o' factorials every time. So you can simply compare the
    product-of-probabilities. You could then optimize this to a bunch of muls
    and adds by working in log-probabilities (and people commonly do), but this
    does not, because I don't want to deal with characters of frequency 0.
    """
    p = 1
    # Instead of computing a histogram and raising things to powers, go straight
    # through and multiply byte-by-byte.
    for c in vec:
        p *= ENGLISH_BYTE_FREQUENCIES[c]
    return p

# Python's string.printable with some of the obviously unprintable
# stuff deleted (I think this is as weird a comment as you do.)
PRINTABLE_BYTES = set(
    b'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!'
    b'"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n')
def is_printable(vec):
    """Does this byte vector represent an ASCII printable string?"""
    return all(c in PRINTABLE_BYTES for c in vec)


def crack_xorchar(vec, metric=english_words_metric):
    """Attempts to crack the xorchar "encryption" applied to byte array 'vec'"""
    decrypts = [(c, xorchar(c, vec)) for c in range(256)]
    decrypts.sort(key=lambda t: metric(t[1]))
    decrypts.reverse()
    return decrypts


def run_p3():
    decrypts = crack_xorchar(h2b(INPUT_3))

    k, t = decrypts[0]
    print('Problem 3')
    print('Best key is:', k)
    print('Best plaintext is:', t)
    #print('Others:')
    #for k, t in decrypts[:10]:
    #    print(k, english_letters_metric(t), t)

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
    # Metric score, original line, decryption key, decrypted text
    possibilities = []
    for i in range(len(INPUT_4)):
        ctext = INPUT_4[i]
        decrypts = crack_xorchar(h2b(ctext))
        decrypts = [(english_letters_metric(d), i, k, d) for k, d in decrypts]
        possibilities.extend(decrypts)

    # Sort by english_letters_metric meaningfulness.
    possibilities.sort()
    possibilities.reverse()

    # I used this for debugging. Turns out the top answer won. How convenient!
    #for p in possibilities[:5]:
    #    print(p)

    s, i, k, d = possibilities[0]
    print('Best decrypt was on line', i+1, 'with key =', k,'and score', s)
    print('Plaintext:', d)
    print()


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
    print('Problem 5')
    print('Encoding ASCII string', repr(INPUT_5), 'with key', repr(KEY_5))
    #print('Decoded expected output:',
    #      repr(xorbytes(KEY_5.encode(), h2b(OUTPUT_5))))
    print('Expected output:', OUTPUT_5)
    output = b2h(xorbytes(KEY_5.encode(), INPUT_5.encode()))
    print('Actual output:  ', output)
    assert(output == OUTPUT_5)
    print()


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

def repeating_key_group(key_length, seq):
    """
    >>> repeating_key_group(2, range(11))
    [(0, 2, 4, 6, 8), (1, 3, 5, 7, 9)]
    >>> repeating_key_group(2, b'abcdefg')
    [(97, 99, 101), (98, 100, 102)]
    """
    iters = [iter(seq)]*key_length
    return list(zip(*zip(*iters)))


import functools
def prod(iterable):
    return functools.reduce(lambda x,y: x*y, iterable, 1)


def xorbytes_printable_keyspace(key_length, ciphertext):
    def search(block):
        decrypts = crack_xorchar(block)
        for k, d in decrypts:
            if is_printable(bytes([k])) and is_printable(d):
                yield english_letters_metric(d), k

    blocks = [bytearray(g) for g in repeating_key_group(key_length, ciphertext)]
    solnsets = [list(search(b)) for b in blocks]
    return solnsets

def countkeys(keyspace):
    return prod([len(seq) for seq in keyspace])

def run_p6():
    print('Problem 6')
    gibberish = b642b(INPUT_6)
    # Run the Hamming autocorrelations by length
    candidates = []
    for length in range(1,50):
        # Chop up into groups. Drop the last one.
        reduced_length = (len(gibberish) // length) * length
        groups = list(grouper(length, gibberish[:reduced_length]))
        pairs = zip(groups[:-1], groups[1:])
        norm_distances = [hamming_distance(a,b)/length for a,b in pairs]
        avg_dist = sum(norm_distances) / len(norm_distances)
        #print(length, avg_dist, len(gibberish) / length)
        candidates.append((avg_dist, length))
    candidates.sort()
    print('Lowest-Hamming 5:')
    for dist, length in candidates[:5]:
        print(length, dist)
    _, length = candidates[0]
    print('Choosing key length', 29)
    keyspace = xorbytes_printable_keyspace(length, gibberish)
    assert(countkeys(keyspace) > 0)
    print('Length', length)
    print(countkeys(keyspace), 'possible keys.')
    [l.sort(reverse=True) for l in keyspace]
    bestkey = bytes(max(l)[1] for l in keyspace)
    print('Highest scoring key:', bestkey)
    print('First three lines of plaintext:')
    for line in xorbytes(bestkey, gibberish).decode().splitlines()[:3]:
        print('>', line)
    print()
        

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

"""

from Crypto.Cipher import AES

def run_p7():
    print('Problem 7')
    INPUT_7 = open('set1p7.txt').read()
    binary = b642b(INPUT_7)
    aes = AES.new(b'YELLOW SUBMARINE', AES.MODE_ECB)
    message = aes.decrypt(binary).decode()
    print('First three lines of plaintext:')
    for l in message.splitlines()[:5]:
        print('>', l)
    print()

    

"""
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

def run_p8():
    print('Problem 8')
    INPUT_8 = open('set1p8.txt').read()
    input_lines = INPUT_8.splitlines()
    # Don't bother hex-decoding this. Just use 32-byte blocks from the
    # original (corresponding to 16-byte blocks in the decoded
    # binary).
    blocksize = 32
    # For each line, find the set of unique blocks that appear in it.
    input_lines_reduced = []
    for line in input_lines:
        input_lines_reduced.append(set(grouper(blocksize, line)))
    # Since we need to remember the original position of the found
    # line in the file, sort the array indices by the size of the
    # unique-set.
    indices = sorted(range(len(input_lines_reduced)),
                     key=lambda i: len(input_lines_reduced[i]))
    # Print out the top 5 candidates (line numbers are the array index
    # plus one). Commented out because the solution is cleaner.
    #for index in indices:
    #    print(index+1,":", len(input_lines_reduced[index]), 'unique blocks.')
    solution = indices[0] + 1
    print('Line', solution, 'is probably ECB-encrypted.')
    print()

if __name__=='__main__':
    if doctest.testmod()[0] == 0:
        run_p1()
        run_p2()
        run_p3()
        run_p4()
        run_p5()
        #dictionary_attack_p6()  # that totally did not work
        run_p6()
        run_p7()
        run_p8()
