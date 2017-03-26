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

import doctest
def load_tests(loader, tests, ignore):
    tests.addTests(doctest.DocTestSuite())
    return tests
