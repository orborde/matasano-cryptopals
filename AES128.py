import os

import util

from set1 import xorvec

from Crypto.Cipher import AES

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

def AES128_CBC_encrypt(plaintext, key, iv=None):
    if iv is None:
        iv = os.urandom(BLOCKSIZE)
    last_cipherblock = iv
    ciphertext = bytearray(iv)
    for block in util.grouper(BLOCKSIZE, plaintext):
        block = bytes(block)
        encrypt = AES128_encrypt(
            xorvec(last_cipherblock, block), key)
        ciphertext.extend(encrypt)
        last_cipherblock = encrypt
    return ciphertext

def AES128_CBC_decrypt(ciphertext, key):
    blocks = list(util.grouper(BLOCKSIZE, ciphertext))
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

def AES128_CTR_keystream(key, nonce):
    assert(len(nonce) == BLOCKSIZE // 2)
    ctr = 0
    while True:
        next_plaintext = nonce + util.int2bytes(ctr, BLOCKSIZE//2)
        for c in AES128_encrypt(next_plaintext, key):
            yield c
        ctr += 1

CTR_TEST = b'hello potato, i am a cheese'
def AES128_CTR_crypt(key, nonce, data):
    """
    # Isn't this a hilarious test?
    >>> AES128_CTR_crypt(b'YELLOW SUBMARINE', 1, CTR_TEST) != CTR_TEST
    True
    >>> AES128_CTR_crypt(b'YELLOW SUBMARINE', 1, AES128_CTR_crypt(b'YELLOW SUBMARINE', 1, CTR_TEST)) == CTR_TEST
    True
    """
    nonce = util.int2bytes(nonce, BLOCKSIZE//2)
    return bytes(x^y for x, y in zip(AES128_CTR_keystream(key, nonce), data))


import doctest
def load_tests(loader, tests, ignore):
    tests.addTests(doctest.DocTestSuite())
    return tests
