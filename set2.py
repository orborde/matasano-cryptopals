#!/usr/bin/env python3

import collections
import doctest
import math
import os
import random
import sys

from set1 import b2b64, b642b, grouper, xorvec

"""
// ------------------------------------------------------------

9. Implement PKCS#7 padding

Pad any block to a specific block length, by appending the number of
bytes of padding to the end of the block. For instance,

  "YELLOW SUBMARINE"

padded to 20 bytes would be:

  "YELLOW SUBMARINE\x04\x04\x04\x04"

The particulars of this algorithm are easy to find online.
"""

INPUT_9 = b'YELLOW SUBMARINE'
OUTPUT_9 =  b'YELLOW SUBMARINE\x04\x04\x04\x04'

def pkcs7pad(data, blocksize):
    """
    >>> pkcs7pad(b'YELLOW SUBMARINE', 20) == b'YELLOW SUBMARINE\x04\x04\x04\x04'
    True
    >>> pkcs7pad(b'YELLOW SUBMARINE', 16) == b'YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10'
    True
    """
    blocks = len(data) // blocksize
    remainder = len(data) % blocksize
    padlen = blocksize - remainder
    padchar = bytes([padlen])
    data = data + (padchar * padlen)
    return data
        

def pkcs7unpad(data):
    """
    >>> pkcs7unpad(b'YELLOW SUBMARINE\x04\x04\x04\x04')
    b'YELLOW SUBMARINE'
    >>> pkcs7unpad(b'YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10')
    b'YELLOW SUBMARINE'
    >>> pkcs7unpad(b'ICE ICE BABY\x04\x04\x04\x04')
    b'ICE ICE BABY'
    >>> pkcs7unpad(b'ICE ICE BABY\x05\x05\x05\x05')
    Traceback (most recent call last):
      ...
    Exception: Bad padding!
    >>> pkcs7unpad(b'ICE ICE BABY\x01\x02\x03\x04')
    Traceback (most recent call last):
      ...
    Exception: Bad padding!

    """
    padlen = data[-1]
    for c in data[-padlen:]:
        if c != padlen:
            raise Exception('Bad padding!')
    return data[:-padlen]


def run_p9():
    print('Problem 9')
    print('Expected output:', OUTPUT_9)
    output = pkcs7pad(INPUT_9, 20)
    assert(output == OUTPUT_9)
    print('Actual output:  ', output)
    print()


"""

// ------------------------------------------------------------

10. Implement CBC Mode

In CBC mode, each ciphertext block is added to the next plaintext
block before the next call to the cipher core.

The first plaintext block, which has no associated previous ciphertext
block, is added to a "fake 0th ciphertext block" called the IV.

Implement CBC mode by hand by taking the ECB function you just wrote,
making it encrypt instead of decrypt (verify this by decrypting
whatever you encrypt to test), and using your XOR function from
previous exercise.

DO NOT CHEAT AND USE OPENSSL TO DO CBC MODE, EVEN TO VERIFY YOUR
RESULTS. What's the point of even doing this stuff if you aren't going
to learn from it?

The buffer at:

    https://gist.github.com/3132976

is intelligible (somewhat) when CBC decrypted against "YELLOW
SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)

"""

from Crypto.Cipher import AES

# We're all about the AES128 here!
KEYSIZE=16
BLOCKSIZE=16

def AES128_encrypt(plaintext, key):
    assert(len(key) == KEYSIZE)
    aes = AES.new(key, AES.MODE_ECB)
    ciphertext = aes.encrypt(plaintext)
    return ciphertext

def AES128_decrypt(ciphertext, key):
    assert(len(key) == KEYSIZE)
    aes = AES.new(key, AES.MODE_ECB)
    plaintext = aes.decrypt(ciphertext)
    return plaintext

def AES128_CBC_encrypt(plaintext, key):
    iv = os.urandom(BLOCKSIZE)
    last_cipherblock = iv
    ciphertext = bytearray(iv)
    for block in grouper(BLOCKSIZE, plaintext):
        block = bytes(block)
        encrypt = AES128_encrypt(
            xorvec(last_cipherblock, block), key)
        ciphertext.extend(encrypt)
        last_cipherblock = encrypt
    return ciphertext

def AES128_CBC_decrypt(ciphertext, key):
    blocks = list(grouper(BLOCKSIZE, ciphertext))
    # Initialization vector
    last_cipherblock = blocks[0]
    plaintext = bytearray()
    for block in blocks[1:]:
        block = bytes(block)
        decrypt = AES128_decrypt(block, key)
        decrypt = xorvec(last_cipherblock, decrypt)
        plaintext.extend(decrypt)
        last_cipherblock = block
    return plaintext

def run_p10():
    print('Problem 10')
    INPUT = b642b(open('set2p10.txt').read())
    KEY = b'YELLOW SUBMARINE'
    IV = bytes(BLOCKSIZE)
    output = AES128_CBC_decrypt(IV + INPUT, KEY)
    print('First 3 lines of output:')
    for line in output.splitlines()[:3]:
        print(line.decode())
    print()

"""
// ------------------------------------------------------------

11. Write an oracle function and use it to detect ECB.

Now that you have ECB and CBC working:

Write a function to generate a random AES key; that's just 16 random
bytes.

Write a function that encrypts data under an unknown key --- that is,
a function that generates a random key and encrypts under it.

The function should look like:

encryption_oracle(your-input)
 => [MEANINGLESS JIBBER JABBER]

Under the hood, have the function APPEND 5-10 bytes (count chosen
randomly) BEFORE the plaintext and 5-10 bytes AFTER the plaintext.

Now, have the function choose to encrypt under ECB 1/2 the time, and
under CBC the other half (just use random IVs each time for CBC). Use
rand(2) to decide which to use.

Now detect the block cipher mode the function is using each time.

"""

def p11_oracle(data):
    # Generate a random key
    key = os.urandom(KEYSIZE)
    # Munge the data
    data = (os.urandom(random.randint(5, 10)) +
            data +
            os.urandom(random.randint(5, 10)))
    encryption = random.choice([AES128_encrypt, AES128_CBC_encrypt])
    return encryption(pkcs7pad(data, BLOCKSIZE), key), encryption

def is_ecb(ciphertext):
    # It is overwhelmingly likely that CBC will scramble things enough
    # that there will be no identical blocks. Meanwhile, ECB will have
    # many duplicate blocks because I'm passing in all zeros (see
    # below).
    blocks = list(grouper(BLOCKSIZE, ciphertext))
    return (len(set(blocks)) != len(blocks))

def run_p11():
    print('Problem 11')
    # Just throw in a very long zero vector
    data = bytes(BLOCKSIZE * 100)
    runs = 0
    correct = 0
    for i in range(1000):
        runs += 1
        ciphertext, encryption = p11_oracle(data)
        if is_ecb(ciphertext):
            guess = AES128_encrypt
        else:
            guess = AES128_CBC_encrypt
        if encryption is guess:
            correct += 1

    print('Out of', runs, 'tries, the classifier got', correct, 'correct.')
    if runs == correct:
        print('NOT BAD!')
    print()

"""
// ------------------------------------------------------------

12. Byte-at-a-time ECB decryption, Full control version

Copy your oracle function to a new function that encrypts buffers
under ECB mode using a consistent but unknown key (for instance,
assign a single random key, once, to a global variable).

Now take that same function and have it append to the plaintext,
BEFORE ENCRYPTING, the following string:

  Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
  aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
  dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
  YnkK

SPOILER ALERT: DO NOT DECODE THIS STRING NOW. DON'T DO IT.

Base64 decode the string before appending it. DO NOT BASE64 DECODE THE
STRING BY HAND; MAKE YOUR CODE DO IT. The point is that you don't know
its contents.

What you have now is a function that produces:

  AES-128-ECB(your-string || unknown-string, random-key)

You can decrypt "unknown-string" with repeated calls to the oracle
function!

Here's roughly how:

a. Feed identical bytes of your-string to the function 1 at a time ---
start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the
block size of the cipher. You know it, but do this step anyway.

b. Detect that the function is using ECB. You already know, but do
this step anyways.

c. Knowing the block size, craft an input block that is exactly 1 byte
short (for instance, if the block size is 8 bytes, make
"AAAAAAA"). Think about what the oracle function is going to put in
that last byte position.

d. Make a dictionary of every possible last byte by feeding different
strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB",
"AAAAAAAC", remembering the first block of each invocation.

e. Match the output of the one-byte-short input to one of the entries
in your dictionary. You've now discovered the first byte of
unknown-string.

f. Repeat for the next byte.
"""

SECRET_SUFFIX_12 = b642b("""
  Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
  aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
  dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
  YnkK
""")

KEY_12 = os.urandom(KEYSIZE)

def secret_suffix_oracle(secret_suffix, data):
    return AES128_encrypt(pkcs7pad(data + secret_suffix, BLOCKSIZE),
                          KEY_12)

def p12_oracle(data):
    return secret_suffix_oracle(SECRET_SUFFIX_12, data)

def find_block_size(oracle):
    def oracle_len(length):
        return len(oracle(bytes(length)))
    start_size = len(oracle(bytes(1)))
    # Run the oracle with successively inputs until the output
    # suddenly gets longer.
    cur_bytes = 1
    while oracle_len(cur_bytes) == start_size:
        cur_bytes += 1
    # OK, the output just jumped in length at cur_size bytes. Now add
    # bytes until it jumps again.
    jump_bytes = cur_bytes
    jump_size = oracle_len(cur_bytes)
    while oracle_len(cur_bytes) == jump_size:
        cur_bytes += 1
    # The output jumped in length again. We now know the block size.
    return (cur_bytes - jump_bytes)

def find_secret_suffix_length(oracle):
    # Work out how many data bytes you need to pass in before the
    # oracle output grows by a block. That's how many bytes short of
    # an even block the oracle suffix is.
    bytes_short = 0
    oracle_null_output_length = len(oracle(b''))
    # Due to the PKCS7 padding, we expect the number of blocks to jump
    # as soon as we reach an even block length.
    while (len(oracle(bytes(bytes_short))) ==
           oracle_null_output_length):
        bytes_short += 1
    return oracle_null_output_length - bytes_short

def find_next_byte(oracle, blocksize, known_prefix):
    # Generate a vector of NULs that, when prepended to the known
    # prefix, bring it to one byte short of a full block.
    chosen_part_len = (-(len(known_prefix) + 1) % blocksize)
    chosen_part = bytes(chosen_part_len)

    # Work out how many blocks of the oracle's output we should know
    # (accounting for the us-controlled varying byte at the end).
    num_known_blocks = math.ceil(
        (len(chosen_part) + len(known_prefix) + 1) /
        blocksize)

    # Generate the oracle output such that its hidden prefix is
    # aligned with the start of our known_prefix. We'll be looking at
    # the first num_known_blocks blocks below.
    oracle_output = oracle(chosen_part)
    oracle_output_start = oracle_output[:(num_known_blocks*blocksize)]

    # Test each possible next-byte of the known prefix in turn. The
    # first num_known_blocks of one of them should match the first
    # num_known_blocks of oracle_output.
    for next_byte in range(256):
        stimulus = chosen_part + known_prefix + bytes([next_byte])
        if oracle(stimulus).startswith(oracle_output_start):
            return next_byte

    # Hmm. That didn't work. PANIC.
    assert(False)


def run_p12():
    print('Problem 12')
    oracle = p12_oracle
    blocksize = find_block_size(oracle)
    print('Block size is', blocksize, 'bytes.')
    ecb_check_data = list(grouper(blocksize, oracle(bytes(1000))))
    if len(set(ecb_check_data)) == len(ecb_check_data):
        print('...not ECB, apparently. Huh?')
        return
    else:
        print('ECB detected, as expected.')

    secret_suffix_length = find_secret_suffix_length(oracle)
    print('The secret suffix is', secret_suffix_length, 'bytes long.')

    known_prefix = bytearray()
    for i in range(secret_suffix_length):
        #print(known_prefix)
        next_byte = find_next_byte(oracle, blocksize, known_prefix)
        known_prefix.append(next_byte)
    secret_suffix = known_prefix
    #print(len(secret_suffix), secret_suffix)

    if not secret_suffix == SECRET_SUFFIX_12:
        print("WE'RE WRONNNNNNGGG!")
        return

    print('We got it!')
    test_data = b'Hi there!'
    assert(secret_suffix_oracle(secret_suffix, test_data) ==
           oracle(test_data))

    print('The secret suffix was:')
    print(secret_suffix.decode())
    print()


"""
// ------------------------------------------------------------

13. ECB cut-and-paste

Write a k=v parsing routine, as if for a structured cookie. The
routine should take:

   foo=bar&baz=qux&zap=zazzle

and produce:

  {
    foo: 'bar',
    baz: 'qux',
    zap: 'zazzle'
  }

(you know, the object; I don't care if you convert it to JSON).

Now write a function that encodes a user profile in that format, given
an email address. You should have something like:

  profile_for("foo@bar.com")

and it should produce:

  {
    email: 'foo@bar.com',
    uid: 10,
    role: 'user'
  }

encoded as:

  email=foo@bar.com&uid=10&role=user

Your "profile_for" function should NOT allow encoding metacharacters
(& and =). Eat them, quote them, whatever you want to do, but don't
let people set their email address to "foo@bar.com&role=admin".

Now, two more easy functions. Generate a random AES key, then:

 (a) Encrypt the encoded user profile under the key; "provide" that
 to the "attacker".

 (b) Decrypt the encoded user profile and parse it.

Using only the user input to profile_for() (as an oracle to generate
"valid" ciphertexts) and the ciphertexts themselves, make a role=admin
profile.

"""

def profile_decode(s):
    """
    >>> profile_decode('uid=bar&email=qux&role=zazzle')
    {'role': 'zazzle', 'uid': 'bar', 'email': 'qux'}
    """
    d = {}  # Dictionaries are like objects, right?
    for kv in s.split('&'):
        k, v = kv.split('=', 1)
        d[k] = v
    return d

def profile_encode(d):
    # Helpfully put the keys in the order that makes it easy to apply
    # cut-and-paste.
    keys = ['email', 'uid', 'role']
    out = '&'.join((k + '=' + d[k]) for k in keys)
    return out

def profile_for(email):
    """
    >>> profile_for('bob@g.c')
    'email=bob@g.c&uid=10&role=user'
    """
    # Strip out the metacharacters.
    for c in '&=':
        email = email.replace(c, '')
    d = {'email': email,
         'role' : 'user',
         'uid' : '10'}
    return profile_encode(d)

P13_KEY = os.urandom(KEYSIZE)
def profile_cookie(email):
    return AES128_encrypt(pkcs7pad(profile_for(email).encode(), BLOCKSIZE), P13_KEY)

def profile_cookie_decode(cookie):
    return profile_decode(pkcs7unpad(AES128_decrypt(cookie, P13_KEY)).decode())

def gen_admin_cookie():
    # 1. Create a plaintext using (e.g.) XXXXXXXXXadmin\0b... as the
    #    email to get the ciphertext for the following ('|' is the
    #    block boundary):
    #
    #    email=XXXXXXXXXXXXXX| \
    #    admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b| \
    #    &uid=10&role=user
    #
    #    The idea here is to get that middle "admin" block, which, if
    #    it were to appear as the last block in a PKCS7 padded
    #    plaintext, would decode to the simple "admin"
    admin_plaintext = pkcs7pad(b'admin', BLOCKSIZE)
    right_email = ((BLOCKSIZE - len('email=')) * b'X') + admin_plaintext
    right_ciphertext = profile_cookie(right_email.decode())
    right_block = right_ciphertext[BLOCKSIZE:(2*BLOCKSIZE)]

    # 2. Create a plaintext using XXXXXX email inputs to get the
    #    ciphertext for the following:
    #
    #    email=XXXXX&uid=10&role=|user
    #
    #    Note that the left chunk will need to be two blocks, because
    #    the prefilled data is longer than a block (19 characters).
    left_email = (2*BLOCKSIZE - len('email=') - len('&uid=10&role=')) * 'X'
    left_ciphertext = profile_cookie(left_email)
    left_block = left_ciphertext[:(2*BLOCKSIZE)]

    # 3. Paste the first block (2) and the second block of (1)
    #    together to produce a profile ciphertext. It will represent
    #    the following plaintext:
    #
    #    email=X&uid=10&role=| \
    #    admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b
    #
    #    which PKCS7-unpads to
    #    email=X&uid=10&role=|admin
    admin_cookie = left_block + right_block
    return admin_cookie


def run_p13():
    print('Problem 13')
    cookie = gen_admin_cookie()
    print('Created a cookie')
    decode = profile_cookie_decode(cookie)
    print('It decodes to this object:', decode)
    if decode['role'] == 'admin':
        print('We made an admin cookie!')
    else:
        print('Sadly, we failed at making an admin cookie :-(')
    print()

"""

// ------------------------------------------------------------

14. Byte-at-a-time ECB decryption, Partial control version

Take your oracle function from #12. Now generate a random count of
random bytes and prepend this string to every plaintext. You are now
doing:

  AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)

Same goal: decrypt the target-bytes.

What's harder about doing this?

How would you overcome that obstacle? The hint is: you're using
all the tools you already have; no crazy math is required.

Think about the words "STIMULUS" and "RESPONSE".

// ------------------------------------------------------------
"""

P14_TARGET_BYTES = SECRET_SUFFIX_12

P14_KEY = os.urandom(KEYSIZE)
P14_PREFIX = os.urandom(random.randint(1,50))
def p14_oracle(data):
    return AES128_ECB(pkcs7pad(P14_PREFIX + data + P14_TARGET_BYTES),
                      P14_KEY)

# TODO

"""
15. PKCS#7 padding validation

Write a function that takes a plaintext, determines if it has valid
PKCS#7 padding, and strips the padding off.

The string:

    "ICE ICE BABY\x04\x04\x04\x04"

has valid padding, and produces the result "ICE ICE BABY".

The string:

    "ICE ICE BABY\x05\x05\x05\x05"

does not have valid padding, nor does:

     "ICE ICE BABY\x01\x02\x03\x04"

If you are writing in a language with exceptions, like Python or Ruby,
make your function throw an exception on bad padding.

// ------------------------------------------------------------
"""

############################################################
# See pkcs7unpad and its doctests at the top of this file. #
############################################################

"""

16. CBC bit flipping

Generate a random AES key.

Combine your padding code and CBC code to write two functions.

The first function should take an arbitrary input string, prepend the
string:
        "comment1=cooking%20MCs;userdata="
and append the string:
    ";comment2=%20like%20a%20pound%20of%20bacon"

The function should quote out the ";" and "=" characters.

The function should then pad out the input to the 16-byte AES block
length and encrypt it under the random AES key.

The second function should decrypt the string and look for the
characters ";admin=true;" (or, equivalently, decrypt, split the string
on ;, convert each resulting string into 2-tuples, and look for the
"admin" tuple. Return true or false based on whether the string exists.

If you've written the first function properly, it should not be
possible to provide user input to it that will generate the string the
second function is looking for.

Instead, modify the ciphertext (without knowledge of the AES key) to
accomplish this.

You're relying on the fact that in CBC mode, a 1-bit error in a
ciphertext block:

* Completely scrambles the block the error occurs in

* Produces the identical 1-bit error (/edit) in the next ciphertext
 block.

Before you implement this attack, answer this question: why does CBC
mode have this property?

// ------------------------------------------------------------
"""

P16_KEY = os.urandom(KEYSIZE)
P16_PREFIX = b'comment1=cooking%20MCs;userdata='
P16_SUFFIX = b';comment2=%20like%20a%20pound%20of%20bacon'  
def p16_cookie(userdata):
    """
    >>> print(p16_cookie_decode(p16_cookie(b'hello')).decode())
    comment1=cooking%20MCs;userdata=hello;comment2=%20like%20a%20pound%20of%20bacon
    >>> print(p16_cookie_decode(p16_cookie(b';admin=true;')).decode())
    comment1=cooking%20MCs;userdata=\;admin\=true\;;comment2=%20like%20a%20pound%20of%20bacon
    """
    # Sanitize
    userdata = userdata.replace(b';', b'\\;')
    userdata = userdata.replace(b'=', b'\\=')
    # And go!
    data = (P16_PREFIX + userdata + P16_SUFFIX)
    return AES128_CBC_encrypt(pkcs7pad(data, BLOCKSIZE), P16_KEY)

def p16_cookie_decode(cookie):
    return pkcs7unpad(AES128_CBC_decrypt(cookie, P16_KEY))


if __name__ == '__main__':
    if (doctest.testmod()[0]) > 0:
        sys.exit(1)
    #run_p9()
    #run_p10()
    #run_p11()
    #run_p12()
    #run_p13()
