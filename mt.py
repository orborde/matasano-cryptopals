#! /usr/bin/env python3
# The Mersenne Twister (MT19937, in particular), based on the
# implementation on Wikipedia.

# Some quick Googling around didn't turn up a Python fixed-width
# integer type, so I have, uh, this instead.
def uint32(i):
    return i % (2**32)


def temper(y):
    y = y ^ (y >> 11)
    y = y ^ ((y << 7) & 0x9d2c5680)
    y = y ^ ((y << 15) & 0xefc60000)
    y = y ^ (y >> 18)
    return y

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
                0x6c078965 * ((self.MT[i-1] ^ (self.MT[i-1] >> 30)) + i))

    def extract(self):
        if self.index == 0:
            self.generate_numbers()
        y = self.MT[self.index]
        self.index += 1
        return temper(y)

m = mt()
import random
random.seed(0)
print m.extract(), random.getrandbits(32)
