import util

from set2 import BLOCKSIZE, AES128_encrypt

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
