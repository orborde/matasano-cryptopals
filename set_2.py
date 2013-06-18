#!/usr/bin/env python3

import random

from set_1 import b2b64, b642b, grouper, xorvec

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

def pkcs7(data, blocksize):
    # math.ceil(data/blocksize) * blocksize, in integer math.
    blocks = len(data) // blocksize
    remainder = len(data) % blocksize
    if (remainder):
        padlen = blocksize - remainder
        padchar = bytes([padlen])
        data = data + (padchar * padlen)
    return data
        

def run_p9():
    print('Problem 9')
    print('Expected output:', OUTPUT_9)
    output = pkcs7(INPUT_9, 20)
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

def random_bytes(length):
    return bytes([random.randint(0, 255) for x in range(length)])

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
    iv = random_bytes(BLOCKSIZE)
    last_cipherblock = iv
    ciphertext = bytearray()
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
    key = random_bytes(KEYSIZE)
    # Munge the data
    data = (random_bytes(random.randint(5, 10)) +
            data +
            random_bytes(random.randint(5, 10)))
    encryption = random.choice([AES128_encrypt, AES128_CBC_encrypt])
    return encryption(pkcs7(data, BLOCKSIZE), key), encryption

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

if __name__ == '__main__':
    run_p9()
    run_p10()
    run_p11()
