#!/usr/bin/env python3

P16_KEY = os.urandom(AES128.KEYSIZE)
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
    return AES128.CBC_encrypt(pkcs7pad(data, AES128.BLOCKSIZE), P16_KEY)

def p16_cookie_decode(cookie):
    return pkcs7unpad(AES128.CBC_decrypt(cookie, P16_KEY))

def p16_cookie_is_admin(cookie):
    return b'admin=true' in p16_cookie_decode(cookie)

def load_tests(loader, tests, ignore):
    tests.addTests(doctest.DocTestSuite())
    return tests
