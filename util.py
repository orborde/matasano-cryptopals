import itertools

# I'm learning Py3 as I go here. I see that this ridiculous hack is
# still necessary...
# http://stackoverflow.com/questions/5850536/how-to-chunk-a-list-in-python-3
def grouper(n, iterable, padvalue=None):
    "grouper(3, 'abcdefg', 'x') --> ('a','b','c'), ('d','e','f'), ('g','x','x')"
    return itertools.zip_longest(*[iter(iterable)]*n, fillvalue=padvalue)

def zero_prefix(data, size):
    return bytes(size - len(data)) + data

def zero_suffix(data, size):
    return data + bytes(size - len(data))

def int2bytes(n, length):
    """
    >>> int2bytes(2, 5)
    b'\\x02\\x00\\x00\\x00\\x00'
    >>> int2bytes(259, 5)
    b'\\x03\\x01\\x00\\x00\\x00'
    """
    out = bytearray()
    while n:
        out.append(n % 256)
        n = n // 256
    assert(len(out) <= length)
    return bytes(zero_suffix(out, length))

def extended_gcd(a, b):
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = b, a
    while r != 0:
        quotient = old_r // r
        (old_r, r) = (r, old_r - quotient * r)
        (old_s, s) = (s, old_s - quotient * s)
        (old_t, t) = (t, old_t - quotient * t)
    return old_r, old_s, old_t, t, s

def gcd(a, b):
    gcd, _, _, _, _ = extended_gcd(a, b)
    return gcd

def invmod(x, mod):
    """Find the multiplicative inverse of 'x' mod 'mod'.

    >>> invmod(3, 5)
    2
    >>> invmod(17, 3120)
    2753
    """
    gcd, r, _, _, _ = extended_gcd(x, mod)
    if gcd == 1:
        return r % mod
    else:
        return None

import itertools
import unittest
class Invmod(unittest.TestCase):
    def test_lots(self):
        for x in range(1,101):
            for mod in range(x+1, 101):
                ix = invmod(x, mod)
                if ix is None:
                    self.assertNotEqual(gcd(x, mod), 1)
                else:
                    self.assertEqual((x*ix)%mod, 1)

def sumprod(seq):
    q = 1
    for x in seq:
        q *= x
    return q

def crt_invert(mods, residues):
    assert len(mods) == len(residues)
    sm = 0
    for i, t in enumerate(zip(mods, residues)):
        m, r = t
        m_s = sumprod(mods[:i] + mods[(i+1):])
        v = r * m_s * invmod(m_s, m)
        sm += v
    # THE P40 INSTRUCTIONS ARE FULL OF LIIIIIES.
    return sm%sumprod(mods)

import doctest
def load_tests(loader, tests, ignore):
    tests.addTests(doctest.DocTestSuite())
    return tests
