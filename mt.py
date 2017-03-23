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
    >>> getbit(10, 0)
    0
    >>> getbit(11, 0)
    1
    >>> getbit(10, 1)
    1
    >>> getbit(10, 2)
    0
    >>> getbit(10, 3)
    1
    >>> getbit(10, 4)
    0
    >>> getbit(10, 5)
    0
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



def distemper(y):
    pass


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

import unittest
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

