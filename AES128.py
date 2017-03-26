import os

import util

from set1 import xorvec

from Crypto.Cipher import AES

KEYSIZE=16
BLOCKSIZE=16

def encrypt(plaintext, key):
    assert(len(key) == KEYSIZE)
    aes = AES.new(key, AES.MODE_ECB)
    ciphertext = aes.encrypt(plaintext)
    return ciphertext

def decrypt(ciphertext, key):
    assert(len(key) == KEYSIZE)
    aes = AES.new(key, AES.MODE_ECB)
    plaintext = aes.decrypt(ciphertext)
    return plaintext

def CBC_encrypt(plaintext, key, iv=None):
    if iv is None:
        iv = os.urandom(BLOCKSIZE)
    last_cipherblock = iv
    ciphertext = bytearray(iv)
    for block in util.grouper(BLOCKSIZE, plaintext):
        block = bytes(block)
        encrypted = encrypt(
            xorvec(last_cipherblock, block), key)
        ciphertext.extend(encrypted)
        last_cipherblock = encrypted
    return ciphertext

def CBC_decrypt(ciphertext, key):
    blocks = list(util.grouper(BLOCKSIZE, ciphertext))
    # Initialization vector
    last_cipherblock = blocks[0]
    plaintext = bytearray()
    for block in blocks[1:]:
        block = bytes(block)
        decrypted = decrypt(block, key)
        decrypted = xorvec(last_cipherblock, decrypted)
        plaintext.extend(decrypted)
        last_cipherblock = block
    return plaintext

def CTR_block(key, nonce, blocknum):
    assert(len(nonce) == BLOCKSIZE // 2)
    plaintext = nonce + util.int2bytes(blocknum, BLOCKSIZE//2)
    return encrypt(plaintext, key)

def CTR_keystream(key, nonce):
    ctr = 0
    while True:
        for c in CTR_block(key, nonce, ctr):
            yield c
        ctr += 1

CTR_TEST = b'hello potato, i am a cheese'
def CTR_crypt(key, nonce, data):
    """
    # Isn't this a hilarious test?
    >>> CTR_crypt(b'YELLOW SUBMARINE', 1, CTR_TEST) != CTR_TEST
    True
    >>> CTR_crypt(b'YELLOW SUBMARINE', 1, CTR_crypt(b'YELLOW SUBMARINE', 1, CTR_TEST)) == CTR_TEST
    True
    """
    nonce = util.int2bytes(nonce, BLOCKSIZE//2)
    return bytes(x^y for x, y in zip(CTR_keystream(key, nonce), data))


import doctest
def load_tests(loader, tests, ignore):
    tests.addTests(doctest.DocTestSuite())
    return tests
