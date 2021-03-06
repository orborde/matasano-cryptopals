#! /usr/bin/env python3
# The Mersenne Twister (MT19937, in particular), based on the
# implementation on Wikipedia.

# Some quick Googling around didn't turn up a Python fixed-width
# integer type, so I have, uh, this stuff instead.
UINT_MAX = (2 ** 32) - 1
def uint32(i):
    return i & UINT_MAX


def temper(y):
    y = y ^ (y >> 11)
    y = y ^ ((y << 7) & 0x9d2c5680)
    y = y ^ ((y << 15) & 0xefc60000)
    y = y ^ (y >> 18)
    return y


def getbit(n, b):
    """
    >>> getbit(11, 0)
    1
    >>> [getbit(10, i) for i in range(6)]
    [0, 1, 0, 1, 0, 0]
    """
    mask = 1 << b
    return (n & mask) >> b

def setbit(n, b, v):
    """
    >>> setbit(10, 0, 1)
    11
    >>> setbit(10, 0, 0)
    10
    >>> setbit(11, 0, 0)
    10
    >>> setbit(0, 0, 0)
    0
    >>> setbit(0, 3, 1)
    8
    """
    assert v in [0, 1]
    mask = 1 << b
    unset_mask = UINT_MAX ^ mask

    n = n & unset_mask
    if v:
        n = n | mask
    return n


def inv_shr_xor(out, shift):
    """Solves out = y ^ (y >> shift) for y.

    This could be done a great deal faster, probably.

    >>> inv_shr_xor(1337 ^ (1337 >> 11), 11)
    1337
    """
    ans = 0
    # The highest (leftmost) `shift` bits are from the original.
    for bit in range(31, 31-shift, -1):
        ans = setbit(ans, bit, getbit(out, bit))
    # The rest can be deduced working left-to-right.
    for bit in range(31-shift, 0 - 1, -1):
        bv = getbit(out, bit) ^ getbit(ans, bit+shift)
        ans = setbit(ans, bit, bv)
    return ans


def inv_shl_and_xor(out, shift, const):
    """Solves out = y ^ ((y << shift) & const) for y.

    This could be done a great deal faster, probably.

    >>> inv_shl_and_xor(1337 ^ ((1337 << 7) & 0x9d2c5680), 7, 0x9d2c5680)
    1337
    """
    ans = 0
    # The lowest `shift` bits are unchanged.
    for bit in range(shift):
        ans = setbit(ans, bit, getbit(out, bit))
    # Work up the rest of the bits.
    for bit in range(shift, 31+1):
        bv = getbit(out, bit) ^ (getbit(ans, bit-shift) &
                                 getbit(const, bit))
        ans = setbit(ans, bit, bv)
    return ans

def distemper(y):
    #y = y ^ (y >> 18)
    y = inv_shr_xor(y, 18)
    #y = y ^ ((y << 15) & 0xefc60000)
    y = inv_shl_and_xor(y, 15, 0xefc60000)
    #y = y ^ ((y << 7) & 0x9d2c5680)
    y = inv_shl_and_xor(y, 7, 0x9d2c5680)
    #y = y ^ (y >> 11)
    y = inv_shr_xor(y, 11)
    # !!!!!
    return y


import random
import unittest
class InvertOps(unittest.TestCase):
    def test_inv_shr_xor_random(self):
        r = random.Random()
        r.seed(1337)

        for _ in range(100):
            for shift in range(1, 31):
                y = r.randint(0, UINT_MAX)
                out = y ^ (y >> shift)
                cy = inv_shr_xor(out, shift)
                self.assertEquals(cy, y)

    def test_inv_shl_and_xor_random(self):
        r = random.Random()
        r.seed(1337)

        for cycle in range(100):
            for shift in range(1, 31):
                const = 0x9d2c5680
                y = r.randint(0, UINT_MAX)
                out = y ^ ((y << shift) & const)
                cy = inv_shl_and_xor(out, shift, const)
                self.assertEquals(
                    cy, y,
                    'cycle={} shift={}\nexp={:b},\ngot={:b}'.format(
                        cycle, shift, y, cy))

    def test_temper_distemper(self):
        r = random.Random()
        r.seed(1337)

        for cycle in range(10000):
            y = r.randint(0, UINT_MAX)
            ty = temper(y)
            dty = distemper(ty)
            self.assertEquals(dty, y)


class mt:
    def __init__(self, seed=0):
        self.index = 0
        self.MT = [0] * 624
        self.seed(seed)

    def seed(self, seed):
        assert(uint32(seed) == seed)
        self.MT[0] = seed
        for i in range(1, 624):
            self.MT[i] = uint32(
                (0x6c078965 * ((self.MT[i-1] ^ (self.MT[i-1] >> 30))) + i))
        self.index = 624

    def generate_numbers(self):
     for i in range(624):
         y = ((self.MT[i] & 0x80000000)
              + (self.MT[(i+1) % 624] & 0x7fffffff))
         self.MT[i] = self.MT[(i + 397) % 624] ^ (y >> 1)
         if (y % 2) != 0:
             self.MT[i] = self.MT[i] ^ (0x9908b0df)

    def extract(self):
        if self.index >= 624:
            self.generate_numbers()
            self.index = 0
        y = self.MT[self.index]
        self.index += 1
        return temper(y)

import doctest
def load_tests(loader, tests, ignore):
    tests.addTests(doctest.DocTestSuite())
    return tests

class MtGolden(unittest.TestCase):
    def test_vs_golden(self):
        expected_values = []
        with open('mt-seed12345_1000.txt', 'r') as f:
            for l in f:
                expected_values.append(int(l))
        m = mt(12345)
        actual_values = [m.extract() for _ in expected_values]
        self.assertEqual(actual_values, expected_values)


if __name__ == '__main__':
    import doctest
    fails, _ = doctest.testmod()
    assert fails == 0

    m = mt(12345)
    for i in range(1000):
        print(m.extract())

